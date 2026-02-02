# Defense Deployment Guide: Quantum-Proof Air Gap Bridge

## Overview

This guide provides comprehensive instructions for deploying the TersecPot Quantum-Proof Air Gap Bridge in defense and high-security environments. The Air Gap Bridge provides secure data ingress for disconnected networks with post-quantum cryptographic validation.

## System Requirements

### Hardware Requirements
- **Air-Gapped Server**: Disconnected network server for command execution
- **USB Ports**: At least 2 USB ports (Data Port A, Identity Token Port B)
- **WORM Drive**: Write-Once-Read-Many drive for forensic logging
- **Secure Workstation**: Air-gapped machine for key ceremony
- **USB Storage Devices**: Encrypted USB drives for key distribution

### Software Requirements
- **Operating System**: Linux (Ubuntu 20.04+ or RHEL 8+)
- **Kernel Version**: 5.4+ (for USB power control support)
- **Rust Toolchain**: Rust 1.70+ for building
- **System Tools**: mount, umount, lsusb, udev utilities

### Security Requirements
- **Physical Security**: Controlled access to air-gapped server
- **Network Isolation**: Complete network disconnection
- **USB Port Control**: Ability to power cycle USB ports
- **Forensic Logging**: Tamper-evident logging storage

## Installation

### 1. Build the Air Gap Bridge
```bash
cd tercespot
cargo build --release --package airgap
```

### 2. Install System Dependencies
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y udev usbutils mount

# RHEL/CentOS
sudo yum install -y udev usbutils mount
```

### 3. Configure System Permissions
```bash
# Create airgap user
sudo useradd -r -s /bin/false airgap

# Set up USB device permissions
sudo tee /etc/udev/rules.d/99-airgap.rules << EOF
# Allow airgap user to control USB ports
SUBSYSTEM=="usb", GROUP="airgap", MODE="0664"
KERNEL=="ttyUSB*", GROUP="airgap", MODE="0664"
EOF

# Reload udev rules
sudo udevadm control --reload-rules
sudo udevadm trigger
```

### 4. Create Directory Structure
```bash
sudo mkdir -p /opt/tersecpot/airgap
sudo mkdir -p /var/lib/tersecpot/airgap/mount
sudo mkdir -p /var/lib/tersecpot/airgap/worm
sudo mkdir -p /etc/tersecpot/airgap

# Set permissions
sudo chown airgap:airgap /opt/tersecpot/airgap
sudo chown airgap:airgap /var/lib/tersecpot/airgap
sudo chmod 755 /opt/tersecpot/airgap
sudo chmod 755 /var/lib/tersecpot/airgap
```

## Configuration

### 1. Create Air Gap Configuration
```bash
sudo tee /etc/tersecpot/airgap/config.toml << EOF
# USB monitoring directory
usb_monitor_path = "/var/lib/tersecpot/airgap/monitor"

# Mount base directory for USB devices
mount_base_path = "/var/lib/tersecpot/airgap/mount"

# WORM drive path for forensic logging
worm_drive_path = "/var/lib/tersecpot/airgap/worm"

# Execution timeout in milliseconds
execution_timeout = 30000

# Enable verbose logging
verbose = true

# Authorized public keys (base64 encoded)
authorized_keys = [
    "base64_encoded_public_key_1",
    "base64_encoded_public_key_2"
]

# Hardware pulse configuration
[data_port]
device_path = "/dev/ttyUSB0"
serial_number = "DATA_PORT_001"

[identity_port]
device_path = "/dev/ttyUSB1"
serial_number = "IDENTITY_TOKEN_001"
EOF
```

### 2. Generate Post-Quantum Keys
```bash
# Run key ceremony on air-gapped workstation
cd tercespot
cargo run --release --package ceremony --bin ceremony

# This will generate:
# - Private keys on separate USB drives
# - Public keys archive for the Air Gap Bridge
# - Ceremony ID and audit trail
```

### 3. Install Authorized Keys
```bash
# Copy public keys to airgap server
sudo cp /path/to/authorized_keys.json /etc/tersecpot/airgap/

# Extract public keys and convert to base64 for config
python3 -c "
import json
with open('/etc/tersecpot/airgap/authorized_keys.json') as f:
    data = json.load(f)
for officer in data['officers']:
    print(f\"\\\"{officer['public_key_hex']}\\\",\")
"
```

## Deployment Architecture

### Physical Setup
```
[Secure Network]          [Air-Gapped Network]
       |                          |
    [USB Data Port A]    [Air Gap Bridge Server]
       |                          |
    [Identity Token]     [USB Identity Port B]
       |                          |
    [WORM Drive]         [Command Execution]
```

### Security Zones
1. **Zone 1**: Secure network with data preparation
2. **Zone 2**: Air-gapped network with execution
3. **Zone 3**: Forensic logging (WORM drive)

### Data Flow
1. **Preparation**: Commands prepared and signed on secure network
2. **Transfer**: Encrypted .tersec packages transferred via USB
3. **Validation**: Air Gap Bridge validates signatures and identity
4. **Execution**: Commands executed on air-gapped systems
5. **Logging**: All events logged to WORM drive

## Operation Procedures

### Daily Operations

#### 1. Command Preparation
```bash
# On secure network workstation
cd tercespot
cargo run --release --package submitter --bin submitter \
    submit --partial "systemctl restart critical-service" \
    --output /tmp/command.partial --signers 2

# Sign with Officer A key
cargo run --release --package submitter --bin submitter \
    submit --append /tmp/command.partial --role DevOps \
    --key /usb/officer_a/private_key --pubkey /usb/officer_a/public_key

# Sign with Officer B key
cargo run --release --package submitter --bin submitter \
    submit --append /tmp/command.partial --role ComplianceManager \
    --key /usb/officer_b/private_key --pubkey /usb/officer_b/public_key

# Final submission
cargo run --release --package submitter --bin submitter \
    submit --submit /tmp/command.partial
```

#### 2. USB Transfer
```bash
# Copy .tersec package to USB drive
cp /tmp/command.partial /media/usb/command.tersec

# Physically transfer USB to air-gapped network
# Insert into Data Port A
```

#### 3. Identity Token Validation
```bash
# Insert identity token into Port B
# Air Gap Bridge automatically validates both devices
# System ready indicator: ✅ Both ports connected
```

#### 4. Command Execution
```bash
# Air Gap Bridge automatically:
# 1. Mounts USB as read-only, no-exec
# 2. Scans for .tersec packages
# 3. Validates signatures with ML-DSA-44
# 4. Executes command if valid
# 5. Logs all events to WORM drive
```

### Emergency Procedures

#### Break-Glass Protocol
```bash
# In emergency situations, single signature execution
cargo run --release --package submitter --bin submitter \
    submit --partial "emergency-command" \
    --emergency --key /usb/emergency_key

# This triggers:
# - Loud audible alarm
# - SMS/PagerDuty alerts to all stakeholders
# - Enhanced forensic logging
# - Automatic incident report generation
```

#### USB Port Power Control
```bash
# Power off compromised USB port
sudo /opt/tersecpot/airgap/airgap-ctl --power-off sdb1

# Power on after investigation
sudo /opt/tersecpot/airgap/airgap-ctl --power-on sdb1

# Check port status
sudo /opt/tersecpot/airgap/airgap-ctl --status sdb1
```

## Monitoring and Maintenance

### System Monitoring
```bash
# Check Air Gap Bridge status
sudo systemctl status tersecpot-airgap

# View real-time logs
sudo journalctl -u tersecpot-airgap -f

# Check forensic logs
sudo cat /var/lib/tersecpot/airgap/worm/forensic_log.txt
```

### Health Checks
```bash
# Test USB device detection
sudo /opt/tersecpot/airgap/airgap-ctl --test-usb

# Test signature verification
sudo /opt/tersecpot/airgap/airgap-ctl --test-signature

# Test pulse integration
sudo /opt/tersecpot/airgap/airgap-ctl --test-pulse

# Generate health report
sudo /opt/tersecpot/airgap/airgap-ctl --health-report
```

### Maintenance Tasks

#### Weekly Tasks
```bash
# Review forensic logs
sudo /opt/tersecpot/airgap/airgap-ctl --review-logs

# Check WORM drive space
df -h /var/lib/tersecpot/airgap/worm

# Verify USB port functionality
sudo /opt/tersecpot/airgap/airgap-ctl --verify-ports
```

#### Monthly Tasks
```bash
# Key rotation (if required)
cd tercespot
cargo run --release --package ceremony --bin ceremony --rotate

# System backup
sudo tar -czf /backup/airgap-config-$(date +%Y%m%d).tar.gz \
    /etc/tersecpot/airgap/ \
    /var/lib/tersecpot/airgap/

# Security audit
sudo /opt/tersecpot/airgap/airgap-ctl --security-audit
```

## Security Best Practices

### Physical Security
- **Access Control**: Limit physical access to air-gapped server
- **USB Port Locking**: Use physical locks when not in use
- **Surveillance**: Monitor server room with cameras
- **Tamper Detection**: Use tamper-evident seals on critical components

### Operational Security
- **Dual Control**: Always require two officers for critical operations
- **Audit Trail**: Maintain complete audit trail of all operations
- **Incident Response**: Have clear incident response procedures
- **Regular Training**: Train personnel on security procedures

### Cryptographic Security
- **Key Protection**: Store private keys on separate, encrypted USB drives
- **Key Rotation**: Implement regular key rotation schedule
- **Signature Validation**: Always validate signatures before execution
- **Post-Quantum Ready**: All cryptographic operations use NIST PQC standards

## Troubleshooting

### Common Issues

#### USB Device Not Detected
```bash
# Check USB connection
lsusb

# Check udev rules
sudo udevadm info -a -n /dev/sdb1

# Reload udev rules
sudo udevadm control --reload-rules
sudo udevadm trigger
```

#### Signature Verification Failed
```bash
# Check authorized keys
cat /etc/tersecpot/airgap/config.toml | grep authorized_keys

# Verify key format
sudo /opt/tersecpot/airgap/airgap-ctl --verify-keys

# Check package format
file /path/to/package.tersec
```

#### Mount Permission Denied
```bash
# Check mount permissions
ls -la /var/lib/tersecpot/airgap/mount/

# Check USB device permissions
ls -la /dev/sdb1

# Verify airgap user permissions
id airgap
```

#### WORM Drive Full
```bash
# Check available space
df -h /var/lib/tersecpot/airgap/worm

# Archive old logs
sudo tar -czf /backup/forensic-logs-$(date +%Y%m).tar.gz \
    /var/lib/tersecpot/airgap/worm/*.txt

# Clean up archived logs (after verification)
sudo rm /var/lib/tersecpot/airgap/worm/*.txt
```

### Emergency Recovery

#### System Compromise
```bash
# Immediate actions:
# 1. Power off all USB ports
sudo /opt/tersecpot/airgap/airgap-ctl --power-off-all

# 2. Isolate server from network (if applicable)
# 3. Document incident
# 4. Contact security team
# 5. Preserve forensic evidence
```

#### Key Loss
```bash
# Emergency key generation (requires dual approval)
cd tercespot
cargo run --release --package ceremony --bin ceremony --emergency-keygen

# Update configuration with new keys
# Notify all authorized personnel
# Update audit logs
```

## Compliance and Auditing

### Regulatory Compliance
- **NIST Standards**: Compliant with NIST PQC and cybersecurity frameworks
- **DoD Requirements**: Meets Department of Defense air gap requirements
- **Industry Standards**: Aligns with defense industry best practices

### Audit Requirements
- **Complete Logging**: All operations logged to WORM drive
- **Tamper Evidence**: Forensic logs are tamper-evident
- **Regular Reviews**: Scheduled audit log reviews
- **Incident Reporting**: Automated incident reporting

### Documentation Requirements
- **Configuration Records**: All configuration changes documented
- **Key Management**: Complete key lifecycle documentation
- **Operational Procedures**: Detailed SOPs for all operations
- **Training Records**: Personnel training and certification records

## Support and Maintenance

### Support Contacts
- **Technical Support**: support@tersecpot.example
- **Security Incidents**: security@tersecpot.example
- **Emergency Response**: emergency@tersecpot.example

### Maintenance Schedule
- **Daily**: System health checks
- **Weekly**: Log reviews and basic maintenance
- **Monthly**: Security audits and key management
- **Quarterly**: Comprehensive system review
- **Annually**: Full security assessment

---

**Document Version**: 1.0  
**Last Updated**: January 3, 2026  
**Next Review**: April 3, 2026  
**Classification**: RESTRICTED - Defense Use Only