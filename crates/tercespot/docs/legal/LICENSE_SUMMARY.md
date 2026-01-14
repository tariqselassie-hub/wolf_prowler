# TersecPot License Summary

## Overview

This document provides a comprehensive summary of the licensing information for the TersecPot Four-Eyes Vault project, including the main project license and all third-party dependencies.

## Main Project License

### MIT License
**File**: [`LICENSE`](LICENSE)

**Copyright**: 2026 TersecPot Contributors

**Key Terms**:
- ✅ Free for commercial and non-commercial use
- ✅ Modification and distribution allowed
- ✅ Private use permitted
- ✅ No liability for authors/copyright holders
- ✅ Requires preservation of copyright notice and license text

**Additional Four-Eyes Vault Terms**:
- Security responsibility lies with users
- Cryptographic algorithm security assumed
- Key management is user responsibility
- Policy configuration requires careful review
- Audit and compliance are user responsibilities
- Intended for security professionals

## Third-Party Dependencies

### Core Cryptographic Dependencies

#### Post-Quantum Cryptography
- **fips204 0.4.6** - ML-DSA-44 signatures
  - License: MIT
  - Purpose: Post-quantum digital signatures
  - Security: NIST PQC Security Level 5

- **fips203 0.4.6** - ML-KEM-1024 encryption
  - License: MIT
  - Purpose: Post-quantum key encapsulation
  - Security: NIST PQC Security Level 5

#### Symmetric Cryptography
- **aes-gcm 0.10.3** - AES-256-GCM encryption
  - License: MIT
  - Purpose: Symmetric encryption with authentication
  - Security: 256-bit symmetric security

### System Dependencies
- **libc 0.2.179** - System interface
  - License: MIT
  - Purpose: Low-level system operations

- **getrandom 0.2.16/0.3.4** - Random number generation
  - License: MIT
  - Purpose: Cryptographically secure random numbers

### Utility Dependencies
- **serde 1.0.217** - Serialization
  - License: MIT OR Apache-2.0
  - Purpose: JSON and data serialization

- **toml 0.8.23** - Configuration parsing
  - License: MIT
  - Purpose: TOML configuration file parsing

- **clap 4.5.27** - Command-line interface
  - License: MIT
  - Purpose: CLI argument parsing

- **notify 6.0** - File system monitoring
  - License: CC0-1.0 OR Artistic-2.0
  - Purpose: Detecting file changes in Postbox


## License Compatibility

### MIT License Compatibility
All dependencies are compatible with the MIT license:
- ✅ All dependencies use permissive licenses (MIT, Apache-2.0)
- ✅ No copyleft or viral licenses present
- ✅ Commercial use permitted for all components
- ✅ Redistribution allowed for all components

### License Requirements
When redistributing TersecPot:
1. **Preserve all license notices** from third-party dependencies
2. **Include this LICENSE_SUMMARY.md** file
3. **Include the main LICENSE** file
4. **Include THIRD_PARTY_LICENSES.md** file
5. **No additional restrictions** beyond those in the licenses

## Security-Related Licensing

### Cryptographic Algorithm Licenses
- **NIST Standards**: ML-DSA-44 and ML-KEM-1024 are NIST standards
- **Open Source**: All cryptographic implementations are open source
- **No Patent Restrictions**: No known patent encumbrances
- **Export Compliance**: Users responsible for export control compliance

### Security Responsibility
The licenses for cryptographic components include:
- **No Warranty**: Cryptographic algorithms provided "as is"
- **User Responsibility**: Security configuration is user responsibility
- **Compliance**: Users must comply with cryptographic regulations

## License Headers in Source Code

### Required Headers
All source files should include appropriate license headers:

```rust
// MIT License
//
// Copyright (c) 2025 TersecPot Contributors
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
```

## Compliance and Auditing

### License Compliance
- **Automated Scanning**: Use cargo-license or similar tools
- **Regular Audits**: Quarterly license compliance reviews
- **Dependency Updates**: Monitor for license changes
- **Documentation**: Maintain up-to-date license documentation

### Security Compliance
- **Cryptographic Standards**: NIST PQC compliance
- **Export Controls**: ITAR/EAR compliance for cryptographic exports
- **Regulatory**: Industry-specific compliance (HIPAA, PCI-DSS, etc.)
- **Audit Trails**: Maintain cryptographic operation logs

## Contact and Support

### License Questions
For questions about licensing:
- **Email**: licensing@tersecpot.example
- **Documentation**: See project documentation
- **Community**: GitHub discussions

### Security Questions
For security-related questions:
- **Security Team**: security@tersecpot.example
- **Vulnerability Reporting**: security@tersecpot.example
- **Response Time**: 48 hours for security issues

## Version History

### License Changes
- **v1.0** (2026-01-03): Initial license documentation
- **Future**: License changes will be documented here

### Dependency Changes
- **Regular Updates**: Dependencies updated with license verification
- **Breaking Changes**: Major license changes will be documented
- **Compatibility**: Backward compatibility maintained where possible

---

**Document Version**: 1.0  
**Last Updated**: January 3, 2026  
**Next Review**: April 3, 2026  
**Maintainer**: TersecPot Legal Team