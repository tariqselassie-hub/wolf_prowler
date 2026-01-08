#![allow(missing_docs)]
#![allow(missing_docs)]
use wolfsec::security::advanced::notifications::*;
use std::collections::HashMap;

#[tokio::test]
async fn test_notification_engine_basic() {
    let engine = NotificationEngine::new();
    
    // Test with no senders
    let request = NotificationRequest {
        title: "Test Alert".to_string(),
        message: "This is a test message".to_string(),
        priority: NotificationPriority::High,
        metadata: HashMap::new(),
        channels: vec![],
    };
    
    let results = engine.send_notification(request).await;
    assert!(results.is_empty());
}

#[tokio::test]
async fn test_notification_engine_with_mock() {
    struct MockSender {
        name: String,
    }
    
    #[async_trait::async_trait]
    impl NotificationSender for MockSender {
        async fn send(&self, _title: &str, _message: &str, _metadata: &NotificationMetadata) -> anyhow::Result<()> {
            Ok(())
        }
        fn name(&self) -> &str {
            &self.name
        }
    }
    
    let engine = NotificationEngine::new();
    engine.register_sender(Box::new(MockSender { name: "Mock1".to_string() })).await;
    engine.register_sender(Box::new(MockSender { name: "Mock2".to_string() })).await;
    
    let request = NotificationRequest {
        title: "Test Alert".to_string(),
        message: "This is a test message".to_string(),
        priority: NotificationPriority::High,
        metadata: HashMap::new(),
        channels: vec![],
    };
    
    let results = engine.send_notification(request).await;
    assert_eq!(results.len(), 2);
    assert!(results.iter().all(|r| r.success));
}
