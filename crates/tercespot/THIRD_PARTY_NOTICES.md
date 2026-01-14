# Third-Party Notices

TersecPot uses third-party libraries and dependencies. This document provides attribution and license information for all dependencies used in the project.

## Summary

This project uses dependencies under the following licenses:
- **MIT**: 298 packages
- **Apache-2.0**: 215 packages  
- **Apache-2.0 OR MIT**: 183 packages
- **BSD-3-Clause**: 12 packages
- **ISC**: 12 packages
- **Unicode-3.0**: 20 packages
- **MPL-2.0**: 4 packages
- **Zlib**: 5 packages
- **CC0-1.0**: 9 packages
- **BSL-1.0**: 4 packages
- Other permissive licenses

All dependencies are compatible with MIT licensing.

---

## Core Cryptographic Dependencies

### NIST Post-Quantum Cryptography

#### fips203 (ML-KEM-1024)
- **License**: Apache-2.0 OR MIT
- **Purpose**: NIST FIPS 203 - Module-Lattice-Based Key-Encapsulation Mechanism
- **Repository**: https://github.com/integritychain/fips203
- **Copyright**: IntegrityChain Contributors

#### fips204 (ML-DSA-87)
- **License**: Apache-2.0 OR MIT
- **Purpose**: NIST FIPS 204 - Module-Lattice-Based Digital Signature Algorithm
- **Repository**: https://github.com/integritychain/fips204
- **Copyright**: IntegrityChain Contributors

### Symmetric Cryptography

#### aes-gcm
- **License**: Apache-2.0 OR MIT
- **Purpose**: AES-256-GCM authenticated encryption
- **Repository**: https://github.com/RustCrypto/AEADs
- **Copyright**: RustCrypto Developers

#### sha2
- **License**: Apache-2.0 OR MIT
- **Purpose**: SHA-256 cryptographic hash function
- **Repository**: https://github.com/RustCrypto/hashes
- **Copyright**: RustCrypto Developers

---

## Networking Dependencies

#### tokio
- **License**: MIT
- **Purpose**: Asynchronous runtime for Rust
- **Repository**: https://github.com/tokio-rs/tokio
- **Copyright**: Tokio Contributors

#### hyper
- **License**: MIT
- **Purpose**: HTTP library for Rust
- **Repository**: https://github.com/hyperium/hyper
- **Copyright**: Hyper Contributors

#### axum
- **License**: MIT
- **Purpose**: Web application framework
- **Repository**: https://github.com/tokio-rs/axum
- **Copyright**: Tokio Contributors

---

## Serialization Dependencies

#### serde
- **License**: Apache-2.0 OR MIT
- **Purpose**: Serialization framework
- **Repository**: https://github.com/serde-rs/serde
- **Copyright**: Serde Developers

#### serde_json
- **License**: Apache-2.0 OR MIT
- **Purpose**: JSON serialization
- **Repository**: https://github.com/serde-rs/json
- **Copyright**: Serde Developers

#### toml
- **License**: Apache-2.0 OR MIT
- **Purpose**: TOML configuration file parsing
- **Repository**: https://github.com/toml-rs/toml
- **Copyright**: TOML-RS Contributors

---

## Utility Dependencies

#### tracing
- **License**: MIT
- **Purpose**: Application-level tracing and logging
- **Repository**: https://github.com/tokio-rs/tracing
- **Copyright**: Tokio Contributors

#### tracing-subscriber
- **License**: MIT
- **Purpose**: Utilities for implementing tracing subscribers
- **Repository**: https://github.com/tokio-rs/tracing
- **Copyright**: Tokio Contributors

#### thiserror
- **License**: Apache-2.0 OR MIT
- **Purpose**: Derive macro for error types
- **Repository**: https://github.com/dtolnay/thiserror
- **Copyright**: David Tolnay

#### zeroize
- **License**: Apache-2.0 OR MIT
- **Purpose**: Securely zero memory
- **Repository**: https://github.com/RustCrypto/utils
- **Copyright**: RustCrypto Developers

#### chrono
- **License**: Apache-2.0 OR MIT
- **Purpose**: Date and time library
- **Repository**: https://github.com/chronotope/chrono
- **Copyright**: Chrono Contributors

#### rand
- **License**: Apache-2.0 OR MIT
- **Purpose**: Random number generation
- **Repository**: https://github.com/rust-random/rand
- **Copyright**: Rust Random Contributors

---

## File System Monitoring

#### notify
- **License**: CC0-1.0
- **Purpose**: Cross-platform file system notification
- **Repository**: https://github.com/notify-rs/notify
- **Copyright**: Notify Contributors

---

## Complete License Texts

### MIT License

```
MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### Apache License 2.0

```
Apache License
Version 2.0, January 2004
http://www.apache.org/licenses/

TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

1. Definitions.

"License" shall mean the terms and conditions for use, reproduction,
and distribution as defined by Sections 1 through 9 of this document.

"Licensor" shall mean the copyright owner or entity authorized by
the copyright owner that is granting the License.

"Legal Entity" shall mean the union of the acting entity and all
other entities that control, are controlled by, or are under common
control with that entity. For the purposes of this definition,
"control" means (i) the power, direct or indirect, to cause the
direction or management of such entity, whether by contract or
otherwise, or (ii) ownership of fifty percent (50%) or more of the
outstanding shares, or (iii) beneficial ownership of such entity.

"You" (or "Your") shall mean an individual or Legal Entity
exercising permissions granted by this License.

"Source" form shall mean the preferred form for making modifications,
including but not limited to software source code, documentation
source, and configuration files.

"Object" form shall mean any form resulting from mechanical
transformation or translation of a Source form, including but
not limited to compiled object code, generated documentation,
and conversions to other media types.

"Work" shall mean the work of authorship, whether in Source or
Object form, made available under the License, as indicated by a
copyright notice that is included in or attached to the work.

"Derivative Works" shall mean any work, whether in Source or Object
form, that is based on (or derived from) the Work and for which the
editorial revisions, annotations, elaborations, or other modifications
represent, as a whole, an original work of authorship.

"Contribution" shall mean any work of authorship, including
the original version of the Work and any modifications or additions
to that Work or Derivative Works thereof, that is intentionally
submitted to Licensor for inclusion in the Work by the copyright owner
or by an individual or Legal Entity authorized to submit on behalf of
the copyright owner.

2. Grant of Copyright License. Subject to the terms and conditions of
this License, each Contributor hereby grants to You a perpetual,
worldwide, non-exclusive, no-charge, royalty-free, irrevocable
copyright license to reproduce, prepare Derivative Works of,
publicly display, publicly perform, sublicense, and distribute the
Work and such Derivative Works in Source or Object form.

3. Grant of Patent License. Subject to the terms and conditions of
this License, each Contributor hereby grants to You a perpetual,
worldwide, non-exclusive, no-charge, royalty-free, irrevocable
(except as stated in this section) patent license to make, have made,
use, offer to sell, sell, import, and otherwise transfer the Work.

[Full Apache 2.0 license text continues...]
```

---

## Acknowledgments

TersecPot is built on the shoulders of giants. We are grateful to all the open-source contributors whose work makes this project possible.

Special thanks to:
- **NIST** for standardizing post-quantum cryptographic algorithms
- **RustCrypto** project for cryptographic implementations
- **Tokio** team for the async runtime ecosystem
- **Serde** team for serialization infrastructure
- All Rust community contributors

---

## License Compliance

This project complies with all third-party license requirements. All dependencies use permissive licenses compatible with MIT licensing.

For questions about licensing, please contact the TersecPot maintainers.

**Last Updated**: 2026-01-14
