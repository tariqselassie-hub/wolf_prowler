# Security Policy

## Supported Versions

We release patches for security vulnerabilities for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

**IMPORTANT**: Please do NOT report security vulnerabilities through public GitHub issues.

### How to Report

If you discover a security vulnerability in Wolf Prowler, please report it by emailing:

**Security Contact**: tariqselassie@gmail.com

Please include:
- Description of the vulnerability
- Steps to reproduce the issue
- Potential impact
- Suggested fix (if any)

### What to Expect

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 5 business days
- **Status Updates**: Every 7 days until resolved
- **Resolution Timeline**: Critical issues within 30 days

### Disclosure Policy

- We follow responsible disclosure practices
- Security fixes will be released as soon as possible
- Credit will be given to reporters (unless anonymity is requested)
- CVE IDs will be requested for significant vulnerabilities

## Security Features

Wolf Prowler implements multiple layers of security:

### Cryptography
- **Post-Quantum**: ML-DSA-87 (FIPS 204), ML-KEM-1024 (FIPS 203)
- **Symmetric**: AES-256-GCM
- **Hashing**: SHA-256, Blake3

### Network Security
- End-to-end encryption for all P2P communications
- Mutual TLS authentication
- Certificate pinning
- Anti-replay protection

### Access Control
- Multi-party authorization (M-of-N signatures)
- Role-based access control (RBAC)
- Time-bound and geo-fenced policies
- Pulse-based authentication

### Privacy
- Zero-knowledge architecture
- PII detection and blocking
- Encrypted audit logs
- No user data collection or retention

### Memory Security
- Automatic zeroization of sensitive data
- Secure memory handling with `zeroize` crate
- Protected against memory dumps

## Security Audits

This project has not yet undergone a formal security audit. We welcome:
- Security researchers to review the code
- Penetration testing (with prior authorization)
- Code audits and feedback

## Scope

### In Scope
- All code in this repository
- Cryptographic implementations
- Network protocols
- Authentication and authorization mechanisms
- Privacy features

### Out of Scope
- Third-party dependencies (report to upstream)
- Social engineering attacks
- Physical security
- Denial of service attacks against public services

## Best Practices for Users

1. **Keep Updated**: Always use the latest version
2. **Secure Keys**: Protect private keys with hardware security modules
3. **Network Security**: Use firewalls and network segmentation
4. **Audit Logs**: Regularly review audit logs
5. **Incident Response**: Have a plan for security incidents

## Compliance

This software is designed for use by security professionals and complies with:
- NIST Post-Quantum Cryptography Standards (FIPS 203, 204)
- Zero-knowledge privacy principles
- US export control regulations (see EXPORT_CONTROL.md)

## Contact

For security-related questions or concerns:
- **Email**: tariqselassie@gmail.com
- **Maintainer**: Terrence A. Jones

---

**Last Updated**: 2025-01-14
