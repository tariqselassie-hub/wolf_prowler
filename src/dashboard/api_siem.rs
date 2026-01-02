use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use crate::dashboard::state::AppState;

/// Query parameters for SIEM events
#[derive(Debug, Deserialize)]
pub struct SIEMEventQuery {
    /// Start time for query range
    pub start: Option<DateTime<Utc>>,
    /// End time for query range
    pub end: Option<DateTime<Utc>>,
    /// Filter by severity
    pub severity: Option<String>,
    /// Filter by event type
    pub event_type: Option<String>,
    /// Limit number of results
    #[serde(default = "default_limit")]
    pub limit: i64,
}

fn default_limit() -> i64 {
    100
}

/// SIEM event response (simplified for now)
#[derive(Debug, Serialize)]
pub struct SIEMEventResponse {
    pub event_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub severity: String,
    pub source: String,
    pub description: String,
    pub resolved: bool,
}

/// SIEM statistics response
#[derive(Debug, Serialize)]
pub struct SIEMStatisticsResponse {
    pub total_events: i64,
    pub events_by_severity: std::collections::HashMap<String, i64>,
    pub unresolved_count: i64,
    pub recent_events: Vec<SIEMEventResponse>,
}

/// Event resolution request
#[derive(Debug, Deserialize)]
pub struct ResolveEventRequest {
    pub resolved_by: String,
}

/// Get SIEM events with optional filters
pub async fn get_siem_events(
    State(state): State<Arc<AppState>>,
    Query(query): Query<SIEMEventQuery>,
) -> Result<Json<Vec<SIEMEventResponse>>, (StatusCode, String)> {
    // For now, return security events from the in-memory store
    // TODO: Query from database when persistence is integrated
    let security_events = state.security_events.read().await;

    let events: Vec<SIEMEventResponse> = security_events
        .iter()
        .take(query.limit as usize)
        .map(|e| SIEMEventResponse {
            event_id: e.id,
            timestamp: e.timestamp,
            event_type: e.event_type.clone(),
            severity: e.severity.clone(),
            source: e.source.clone(),
            description: e.message.clone(),
            resolved: false,
        })
        .collect();

    Ok(Json(events))
}

/// Get a specific SIEM event by ID
pub async fn get_siem_event(
    State(state): State<Arc<AppState>>,
    Path(event_id): Path<Uuid>,
) -> Result<Json<SIEMEventResponse>, (StatusCode, String)> {
    let security_events = state.security_events.read().await;

    let event = security_events
        .iter()
        .find(|e| e.id == event_id)
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Event not found".to_string()))?;

    Ok(Json(SIEMEventResponse {
        event_id: event.id,
        timestamp: event.timestamp,
        event_type: event.event_type.clone(),
        severity: event.severity.clone(),
        source: event.source.clone(),
        description: event.message.clone(),
        resolved: false,
    }))
}

/// Mark a SIEM event as resolved
pub async fn resolve_siem_event(
    State(_state): State<Arc<AppState>>,
    Path(_event_id): Path<Uuid>,
    Json(_request): Json<ResolveEventRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    // TODO: Implement event resolution in database
    // For now, just return success
    Ok(StatusCode::OK)
}

/// Get SIEM statistics
pub async fn get_siem_statistics(
    State(state): State<Arc<AppState>>,
) -> Result<Json<SIEMStatisticsResponse>, (StatusCode, String)> {
    let security_events = state.security_events.read().await;

    let total_events = security_events.len() as i64;
    let unresolved_count = total_events; // All events unresolved for now

    let mut events_by_severity = std::collections::HashMap::new();
    for event in security_events.iter() {
        *events_by_severity
            .entry(event.severity.clone())
            .or_insert(0) += 1;
    }

    let recent_events: Vec<SIEMEventResponse> = security_events
        .iter()
        .rev()
        .take(10)
        .map(|e| SIEMEventResponse {
            event_id: e.id,
            timestamp: e.timestamp,
            event_type: e.event_type.clone(),
            severity: e.severity.clone(),
            source: e.source.clone(),
            description: e.message.clone(),
            resolved: false,
        })
        .collect();

    Ok(Json(SIEMStatisticsResponse {
        total_events,
        events_by_severity,
        unresolved_count,
        recent_events,
    }))
}

/// Get event timeline for visualization
#[derive(Debug, Serialize)]
pub struct TimelineEntry {
    pub timestamp: DateTime<Utc>,
    pub count: i64,
    pub severity_breakdown: std::collections::HashMap<String, i64>,
}

pub async fn get_siem_timeline(
    State(state): State<Arc<AppState>>,
    Query(_query): Query<SIEMEventQuery>,
) -> Result<Json<Vec<TimelineEntry>>, (StatusCode, String)> {
    let security_events = state.security_events.read().await;

    // Group events by hour
    let mut timeline: std::collections::HashMap<DateTime<Utc>, TimelineEntry> =
        std::collections::HashMap::new();

    for event in security_events.iter() {
        // Round to nearest hour by truncating minutes and seconds
        let hour_timestamp = event.timestamp.format("%Y-%m-%d %H:00:00").to_string();
        let hour =
            DateTime::parse_from_str(&format!("{} +0000", hour_timestamp), "%Y-%m-%d %H:%M:%S %z")
                .unwrap()
                .with_timezone(&Utc);

        let entry = timeline.entry(hour).or_insert(TimelineEntry {
            timestamp: hour,
            count: 0,
            severity_breakdown: std::collections::HashMap::new(),
        });

        entry.count += 1;
        *entry
            .severity_breakdown
            .entry(event.severity.clone())
            .or_insert(0) += 1;
    }

    let mut timeline_vec: Vec<TimelineEntry> = timeline.into_values().collect();
    timeline_vec.sort_by_key(|e| e.timestamp);

    Ok(Json(timeline_vec))
}
