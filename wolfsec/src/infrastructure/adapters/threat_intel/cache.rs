// Simple in-memory cache for threat feed items
use super::ThreatFeedItem;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Simple in-memory cache for threat feed items to reduce API load.
pub struct FeedCache {
    /// Time-to-live for cached items.
    pub ttl: Duration,
    /// Internal storage mapping keys to their cached items and insertion time.
    pub store: HashMap<String, (ThreatFeedItem, Instant)>,
}

impl FeedCache {
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            ttl: Duration::from_secs(ttl_secs),
            store: HashMap::new(),
        }
    }

    pub fn get(&mut self, key: &str) -> Option<ThreatFeedItem> {
        if let Some((item, ts)) = self.store.get(key) {
            if ts.elapsed() < self.ttl {
                return Some(item.clone());
            }
        }
        None
    }

    pub fn set(&mut self, key: String, item: ThreatFeedItem) {
        self.store.insert(key, (item, Instant::now()));
    }
}
