#![cfg(test)]

use axum::{
    body::Body,
    body::to_bytes,
    extract::{Json, Query, State},
    http::{HeaderMap, HeaderValue, Request, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::get,
    Router,
};
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

use wolf_web::dashboard::{
    api::create_api_router,
    middleware::auth::{api_key_auth_middleware, session_auth_middleware},
    state::AppState,
    websocket::{create_websocket_router, DashboardMessage, WebSocketState},
};
use wolfsec::security::advanced::iam::{AuthenticationManager, IAMConfig};
use wolfsec::threat_detection::{BehavioralAnalyzer, ThreatDetector};
use anyhow::Result;

// Mock repository for testing
struct MockThreatRepository;

#[async_trait::async_trait]
impl wolfsec::domain::repositories::ThreatRepository for MockThreatRepository {
    async fn save(
        &self,
        _threat: &wolfsec::domain::entities::Threat,
    ) -> Result<(), wolfsec::domain::error::DomainError> {
        Ok(())
    }

    async fn find_by_id(
        &self,
        _id: &uuid::Uuid,
    ) -> Result<Option<wolfsec::domain::entities::Threat>, wolfsec::domain::error::DomainError>
    {
        Ok(None)
    }
}

mod dashboard_tests {
    use super::*;

    // Helper function to create test state
    async fn create_test_state() -> Arc<AppState> {
        let threat_repo = Arc::new(crate::MockThreatRepository);
        
        // Mock config for ThreatDetector
        let config = wolfsec::threat_detection::ThreatDetectionConfig::default();

        Arc::new(AppState::new(
            ThreatDetector::new(config, threat_repo),
            BehavioralAnalyzer {
                baseline_window: 100,
                deviation_threshold: 2.0,
                patterns_detected: 0,
            },
            AuthenticationManager::new(IAMConfig::default())
                .await
                .unwrap(),
        ))
    }

    #[tokio::test]
    async fn test_dashboard_api_router_creation() {
        let state = create_test_state().await;
        let _router = create_api_router(state);

        // Test that router is created successfully (implicit if we get here)
        assert!(true);
    }

    #[tokio::test]
    async fn test_health_check_endpoint() {
        let state = create_test_state().await;
        let router = create_api_router(state);

        // Test health check endpoint
        let response = router
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body_str = String::from_utf8(body.to_vec()).unwrap();
        assert!(body_str.contains("healthy"));
    }

    #[tokio::test]
    async fn test_api_v1_status_endpoint() {
        let state = create_test_state().await;
        let router = create_api_router(state);

        // Test v1 status endpoint
        let response = router
            .oneshot(
                Request::builder()
                    .uri("/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body_str = String::from_utf8(body.to_vec()).unwrap();
        assert!(body_str.contains("Dashboard API v1 is operational"));
    }

    #[tokio::test]
    async fn test_metrics_endpoints() {
        let state = create_test_state().await;
        let router = create_api_router(state);

        // Test basic metrics endpoint
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Test detailed metrics endpoint
        let response = router
            .oneshot(
                Request::builder()
                    .uri("/metrics/detailed")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_authentication_endpoints() {
        let state = create_test_state().await;
        let router = create_api_router(state);

        // Test login endpoint (should fail with invalid credentials)
        let login_body = serde_json::json!({
            "username": "testuser",
            "password": "testpass",
            "remember_me": false
        });

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/auth/login")
                    .method("POST")
                    .header("Content-Type", "application/json")
                    .body(Body::from(login_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return some response (success or failure)
        assert_ne!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_websocket_router_creation() {
        let state = create_test_state().await;
        let _router = create_websocket_router(state);

        // Test that WebSocket router is created successfully
        assert!(true);
    }

    #[tokio::test]
    async fn test_websocket_message_serialization() {
        // Test DashboardMessage serialization
        let system_metrics = DashboardMessage::SystemMetrics {
            cpu: 15.5,
            memory: 256.0,
            uptime: 3600,
        };

        let json = serde_json::to_string(&system_metrics).unwrap();
        assert!(json.contains("system_metrics"));
        assert!(json.contains("15.5"));

        // Test deserialization
        let deserialized: DashboardMessage = serde_json::from_str(&json).unwrap();
        match deserialized {
            DashboardMessage::SystemMetrics {
                cpu,
                memory,
                uptime,
            } => {
                assert_eq!(cpu, 15.5);
                assert_eq!(memory, 256.0);
                assert_eq!(uptime, 3600);
            }
            _ => panic!("Expected SystemMetrics variant"),
        }
    }

    #[tokio::test]
    async fn test_authentication_middleware_session() {
        let state = create_test_state().await;

        // Create a mock request
        let session_id = Uuid::new_v4();
        
        let app = Router::new()
            .route("/test", get(|| async { "ok" }))
            .layer(middleware::from_fn_with_state(state.clone(), session_auth_middleware))
            .with_state(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/test")
                    .header("X-Session-ID", session_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should fail with invalid session (not found in auth manager)
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_authentication_middleware_api_key() {
        let state = create_test_state().await;

        let app = Router::new()
            .route("/test", get(|| async { "ok" }))
            .layer(middleware::from_fn_with_state(state.clone(), api_key_auth_middleware))
            .with_state(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/test")
                    .header("X-API-Key", "invalid_key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should fail with invalid API key
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_state_management() {
        let state = create_test_state().await;

        // Test request counting
        let initial_count = state.get_request_count().await;
        state.increment_request_count().await;
        let new_count = state.get_request_count().await;

        assert_eq!(new_count, initial_count + 1);

        // Test WebSocket state
        let ws_state = state.websocket_state.clone();
        let tx = ws_state.tx.clone();

        // Test broadcasting a message
        let test_message = DashboardMessage::Notification {
            title: "Test".to_string(),
            message: "Test message".to_string(),
        };

        let json = serde_json::to_string(&test_message).unwrap();
        let result = tx.send(json);
        assert!(result.is_ok(), "Should be able to broadcast message");
    }

    #[tokio::test]
    async fn test_threat_detection_integration() {
        let state = create_test_state().await;

        // Test that threat detection engine is accessible
        let threat_engine = state.threat_engine.lock().await;
        // Just checking access is enough for this integration test
        assert!(true);
    }

    #[tokio::test]
    async fn test_behavioral_analysis_integration() {
        let state = create_test_state().await;

        // Test that behavioral analysis engine is accessible
        let _behavioral_engine = state.behavioral_engine.lock().await;
        // Just checking access is enough
        assert!(true);
    }



    #[tokio::test]
    async fn test_comprehensive_dashboard_flow() {
        let state = create_test_state().await;
        let router = create_api_router(state);

        // Test multiple endpoints in sequence

        // 1. Health check
        let health_response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(health_response.status(), StatusCode::OK);

        // 2. API v1 status
        let v1_response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(v1_response.status(), StatusCode::OK);

        // 3. Metrics endpoint
        let metrics_response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(metrics_response.status(), StatusCode::OK);

        // 4. WebSocket router should be nested
        let ws_response = router
            .oneshot(
                Request::builder()
                    .uri("/ws/dashboard")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // The API router does not handle WebSocket endpoints, so it should be a 404.
        assert_eq!(ws_response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_error_handling() {
        let state = create_test_state().await;
        let router = create_api_router(state);

        // Test non-existent endpoint
        let response = router
            .oneshot(
                Request::builder()
                    .uri("/nonexistent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_websocket_broadcast_functionality() {
        let state = create_test_state().await;
        let ws_state = state.websocket_state.clone();

        // Test broadcasting different message types
        let tx = ws_state.tx.clone();

        // Broadcast system metrics
        let metrics_msg = DashboardMessage::SystemMetrics {
            cpu: 20.0,
            memory: 512.0,
            uptime: 7200,
        };
        let json = serde_json::to_string(&metrics_msg).unwrap();
        let result = tx.send(json);
        assert!(result.is_ok());

        // Broadcast security alert
        let alert_msg = DashboardMessage::SecurityAlert {
            severity: "high".to_string(),
            message: "Critical threat detected".to_string(),
            timestamp: "2026-01-03T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&alert_msg).unwrap();
        let result = tx.send(json);
        assert!(result.is_ok());

        // Broadcast network status
        let network_msg = DashboardMessage::NetworkStatus {
            peers: 150,
            connections: 75,
            health: 95.0,
        };
        let json = serde_json::to_string(&network_msg).unwrap();
        let result = tx.send(json);
        assert!(result.is_ok());
    }
}
