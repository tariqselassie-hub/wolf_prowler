# Territory Marking - Integration Tests

This document provides comprehensive testing procedures for all three phases of the Territory Marking system.

## Prerequisites

```bash
# Ensure Wolf Prowler is running
cargo run --bin wolf_prowler

# Or in release mode for performance testing
cargo build --release
./target/release/wolf_prowler
```

## Phase 1: Wolf Pack Peer Visualization

### Test 1.1: Peer API Endpoint
```bash
# Test peer retrieval
curl -H "X-API-Key: dev-key-12345" \
  http://localhost:3031/api/territory/peers | jq

# Expected: JSON with peers array, zones object, counts
# Verify: total_peers, online_peers, zones (alpha/beta/omega/neutral)
```

### Test 1.2: Zone Classification
```bash
# Verify zone assignment based on trust scores
curl -H "X-API-Key: dev-key-12345" \
  http://localhost:3031/api/territory/peers | \
  jq '.peers[] | {id: .id, trust: .trust_score, zone: .zone}'

# Expected: 
# - trust >= 0.8 → alpha
# - trust >= 0.5 → beta
# - trust >= 0.3 → omega
# - trust < 0.3 → neutral
```

### Test 1.3: Position Calculation
```bash
# Verify circular positioning
curl -H "X-API-Key: dev-key-12345" \
  http://localhost:3031/api/territory/peers | \
  jq '.peers[] | {zone: .zone, position: .position}'

# Expected: position.x and position.y within appropriate radius
# Alpha: ~30, Beta: ~50, Omega: ~70, Neutral: ~90
```

### Test 1.4: Frontend Rendering
1. Navigate to `http://localhost:3031/static/territory_marking.html`
2. Verify:
   - [ ] Peers appear as colored nodes
   - [ ] Colors match zones (Amber/Blue/Purple/Gray)
   - [ ] Nodes are positioned in concentric circles
   - [ ] Clicking nodes shows details
   - [ ] Auto-refresh every 5 seconds

---

## Phase 2: LAN Device Scanning

### Test 2.1: Network Scanner
```bash
# Trigger LAN scan
curl -H "X-API-Key: dev-key-12345" \
  http://localhost:3031/api/territory/scan | jq

# Expected: JSON with devices array, scan_time_ms, cached flag
# First call: cached=false, scan_time_ms > 1000
# Second call (within 5min): cached=true, scan_time_ms < 10
```

### Test 2.2: Device Classification
```bash
# Verify device type detection
curl -H "X-API-Key: dev-key-12345" \
  http://localhost:3031/api/territory/scan | \
  jq '.devices[] | {ip: .ip, hostname: .hostname, type: .device_type}'

# Expected device types:
# - Router: hostname contains "router", "gateway"
# - Printer: hostname contains "printer", "hp", "canon"
# - Phone: hostname contains "phone", "android", "iphone"
# - Computer: hostname contains "pc", "laptop", "desktop"
# - IoT: hostname contains "iot", "smart"
# - Unknown: no match
```

### Test 2.3: Hostname Resolution
```bash
# Check DNS resolution
curl -H "X-API-Key: dev-key-12345" \
  http://localhost:3031/api/territory/scan | \
  jq '.devices[] | select(.hostname != null) | {ip: .ip, hostname: .hostname}'

# Expected: Some devices should have resolved hostnames
```

### Test 2.4: Cache Behavior
```bash
# Test 1: Fresh scan
time curl -H "X-API-Key: dev-key-12345" \
  http://localhost:3031/api/territory/scan > /dev/null

# Test 2: Cached scan (should be much faster)
time curl -H "X-API-Key: dev-key-12345" \
  http://localhost:3031/api/territory/scan > /dev/null

# Expected: Second call significantly faster
```

### Test 2.5: Frontend Integration
1. Navigate to `http://localhost:3031/static/territory_marking.html`
2. Wait for automatic scan or click "Scan Territory"
3. Verify:
   - [ ] LAN devices appear in outer rings
   - [ ] Device type icons displayed (router, monitor, smartphone, etc.)
   - [ ] Colors match device types
   - [ ] Clicking devices shows details (IP, hostname, type, latency)
   - [ ] Scan status indicator updates

---

## Phase 3: GeoIP Integration

### Test 3.1: GeoIP Resolution
```bash
# Test with public IP (Google DNS)
curl -X POST -H "X-API-Key: dev-key-12345" \
  -H "Content-Type: application/json" \
  -d '{"ip":"8.8.8.8"}' \
  http://localhost:3031/api/geoip/resolve | jq

# Expected: Full location data with country, city, lat/lon, ISP
```

### Test 3.2: Multiple IP Resolution
```bash
# Test various IPs
for ip in "1.1.1.1" "8.8.8.8" "208.67.222.222"; do
  echo "Testing $ip:"
  curl -X POST -H "X-API-Key: dev-key-12345" \
    -H "Content-Type: application/json" \
    -d "{\"ip\":\"$ip\"}" \
    http://localhost:3031/api/geoip/resolve | jq '.location | {country, city, isp}'
done

# Expected: Different locations for each IP
```

### Test 3.3: Private IP Filtering
```bash
# Test with private IP
curl -X POST -H "X-API-Key: dev-key-12345" \
  -H "Content-Type: application/json" \
  -d '{"ip":"192.168.1.1"}' \
  http://localhost:3031/api/geoip/resolve | jq

# Expected: location=null (private IPs skipped)
```

### Test 3.4: Cache Statistics
```bash
# Check cache stats
curl -H "X-API-Key: dev-key-12345" \
  http://localhost:3031/api/geoip/stats | jq

# Expected: cache_total, cache_expired, cache_active counts
```

### Test 3.5: World Map Visualization
1. Navigate to `http://localhost:3031/static/territory_marking.html`
2. Click "World Map" button
3. Verify:
   - [ ] Map loads with dark theme
   - [ ] Markers appear for non-local peers
   - [ ] Country flags displayed on markers
   - [ ] Clicking markers shows popup with details
   - [ ] Map auto-fits to show all peers
   - [ ] Can toggle back to Radar view

---

## Performance Testing

### Test P1: Concurrent API Calls
```bash
# Test 10 concurrent peer requests
for i in {1..10}; do
  curl -H "X-API-Key: dev-key-12345" \
    http://localhost:3031/api/territory/peers > /dev/null &
done
wait

# Expected: All requests complete successfully
```

### Test P2: Large Network Scan
```bash
# Measure scan time for /24 subnet
time curl -H "X-API-Key: dev-key-12345" \
  http://localhost:3031/api/territory/scan | \
  jq '{total: .total_devices, time_ms: .scan_time_ms}'

# Expected: < 10 seconds for 254 IPs
```

### Test P3: GeoIP Batch Performance
```bash
# Test multiple GeoIP resolutions
time for ip in "1.1.1.1" "8.8.8.8" "208.67.222.222" "9.9.9.9"; do
  curl -X POST -H "X-API-Key: dev-key-12345" \
    -H "Content-Type: application/json" \
    -d "{\"ip\":\"$ip\"}" \
    http://localhost:3031/api/geoip/resolve > /dev/null
done

# Expected: First calls ~500ms each, cached calls <1ms
```

---

## Error Handling Tests

### Test E1: Invalid API Key
```bash
curl -H "X-API-Key: invalid-key" \
  http://localhost:3031/api/territory/peers

# Expected: 401 Unauthorized or 403 Forbidden
```

### Test E2: Invalid IP Format
```bash
curl -X POST -H "X-API-Key: dev-key-12345" \
  -H "Content-Type: application/json" \
  -d '{"ip":"not-an-ip"}' \
  http://localhost:3031/api/geoip/resolve

# Expected: 400 Bad Request
```

### Test E3: Network Timeout
```bash
# Test with unreachable IP
curl -X POST -H "X-API-Key: dev-key-12345" \
  -H "Content-Type: application/json" \
  -d '{"ip":"10.255.255.1"}' \
  http://localhost:3031/api/geoip/resolve

# Expected: location=null (private IP filtered)
```

---

## Integration Test Suite

### Full System Test
```bash
#!/bin/bash
# Run all tests in sequence

echo "=== Phase 1: Peer Visualization ==="
curl -H "X-API-Key: dev-key-12345" \
  http://localhost:3031/api/territory/peers | jq '.total_peers'

echo "=== Phase 2: LAN Scanning ==="
curl -H "X-API-Key: dev-key-12345" \
  http://localhost:3031/api/territory/scan | jq '.total_devices'

echo "=== Phase 3: GeoIP Resolution ==="
curl -X POST -H "X-API-Key: dev-key-12345" \
  -H "Content-Type: application/json" \
  -d '{"ip":"8.8.8.8"}' \
  http://localhost:3031/api/geoip/resolve | jq '.location.country'

echo "=== Cache Statistics ==="
curl -H "X-API-Key: dev-key-12345" \
  http://localhost:3031/api/geoip/stats | jq

echo "=== All tests complete ==="
```

---

## Success Criteria

### Phase 1 ✅
- [ ] API returns peer data with zones
- [ ] Frontend displays peers in correct positions
- [ ] Zone colors match trust scores
- [ ] Auto-refresh works

### Phase 2 ✅
- [ ] Scanner discovers LAN devices
- [ ] Device types classified correctly
- [ ] Hostnames resolved where possible
- [ ] Cache reduces scan time
- [ ] Frontend shows both peers and devices

### Phase 3 ✅
- [ ] GeoIP resolves public IPs
- [ ] Private IPs filtered correctly
- [ ] Cache prevents duplicate API calls
- [ ] World map displays markers
- [ ] Country flags shown correctly

---

## Troubleshooting

### Issue: No peers showing
**Solution**: Ensure Wolf Prowler has connected peers. Check `cargo run` output for peer connections.

### Issue: LAN scan finds no devices
**Solution**: 
1. Verify `ping` command is available: `which ping`
2. Check subnet configuration (currently hardcoded to 192.168.1.0/24)
3. Ensure firewall allows ICMP

### Issue: GeoIP returns null
**Solution**:
1. Check internet connectivity
2. Verify ip-api.com is accessible: `curl http://ip-api.com/json/8.8.8.8`
3. Check rate limits (45 requests/minute on free tier)

### Issue: World map not loading
**Solution**:
1. Check browser console for errors
2. Verify Leaflet.js loaded: Check Network tab
3. Ensure CSP allows unpkg.com
