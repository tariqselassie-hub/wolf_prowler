use wolfsec::external_feeds::ExternalFeedsConfig;

#[test]
fn test_default_config() {
    let config = ExternalFeedsConfig::default();
    assert_eq!(config.cache_ttl_secs, 3600);
    assert!(config.nvd_api_key.is_none());
}
