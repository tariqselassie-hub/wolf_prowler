# Export Control Notice

## Overview

This software contains cryptographic technology and is subject to United States export control regulations under the Export Administration Regulations (EAR).

## Cryptographic Technology

Wolf Prowler implements the following cryptographic algorithms:

### Post-Quantum Cryptography (NIST Standards)
- **ML-DSA-87** (FIPS 204) - Module-Lattice-Based Digital Signature Algorithm
- **ML-KEM-1024** (FIPS 203) - Module-Lattice-Based Key-Encapsulation Mechanism

### Symmetric Cryptography
- **AES-256-GCM** - Advanced Encryption Standard with Galois/Counter Mode
- **SHA-256** - Secure Hash Algorithm
- **Blake3** - Cryptographic hash function

## Export Control Classification

- **ECCN**: 5D002 (Cryptographic software)
- **License Exception**: TSU (Technology and Software - Unrestricted)
- **Basis**: Publicly available encryption source code

## Distribution Restrictions

### Intended Use
This software is intended for use **within the United States only** by:
- US-based cybersecurity professionals
- US government agencies
- US-based security researchers
- US-based enterprises

### Geographic Restrictions

**IMPORTANT**: This software is NOT authorized for:
- Export to non-US entities
- Use by non-US persons
- Deployment outside the United States
- Distribution to foreign nationals (even within the US)

## Compliance Requirements

### For Users

By downloading, using, or distributing this software, you certify that:

1. You are a **US person** as defined by US export control regulations
2. You will **not export** this software to any foreign country
3. You will **not transfer** this software to any foreign national
4. You understand the **export control restrictions**
5. You will comply with all applicable US export control laws

### Definition of "US Person"

A US person includes:
- US citizens
- US permanent residents (green card holders)
- US corporations and organizations
- US government agencies

## GitHub Access Control

### Repository Settings

**IMPORTANT**: GitHub does not provide built-in geographic access restrictions. To maintain US-only distribution:

1. **Private Repository**: Keep the repository private until you implement access controls
2. **Contributor Verification**: Verify all contributors are US persons
3. **License Agreement**: Require acceptance of export control terms
4. **Access Logs**: Monitor who accesses the repository

### Recommended Practices

1. **Invitation-Only**: Use GitHub's invitation system for collaborators
2. **Organization**: Create a GitHub organization with verified US members
3. **Terms of Use**: Add export control notice to README and LICENSE
4. **Contributor Agreement**: Require signed contributor agreements

## Open Source Considerations

### Public Repository Risks

If you make this repository public on GitHub:
- **Anyone worldwide** can access and download the code
- **GitHub cannot restrict** access by geography
- **You may be in violation** of export control regulations

### Alternatives

1. **Private Repository**: Keep it private, invite US persons only
2. **Self-Hosted**: Host on a US-based server with access controls
3. **BIS Notification**: File one-time notification with Bureau of Industry and Security
4. **Legal Review**: Consult with export control attorney

## BIS Notification (If Going Public)

If you decide to make this publicly available, you should:

1. **File Form BIS-748P**: Encryption Registration
2. **Submit to**: crypt@bis.doc.gov and enc@nsa.gov
3. **Include**: Source code URL, cryptographic details
4. **Timeline**: File before making repository public

### What This Achieves

- Satisfies "publicly available" exception requirements
- Provides legal protection for open-source distribution
- One-time filing (updates only if algorithms change significantly)

## Penalties for Violations

Violations of US export control regulations can result in:
- Civil penalties up to $300,000 per violation
- Criminal penalties up to $1,000,000 and 20 years imprisonment
- Loss of export privileges
- Debarment from government contracts

## Disclaimer

This notice is provided for informational purposes only and does not constitute legal advice. For specific export control questions, consult with:
- A qualified export control attorney
- The Bureau of Industry and Security (BIS)
- Your organization's export compliance officer

## Contact

For questions about export control compliance:
- **Project Maintainer**: Terrence A. Jones <tariqselassie@gmail.com>
- **BIS**: https://www.bis.doc.gov
- **BIS Hotline**: 202-482-4811

## References

- Export Administration Regulations (EAR): 15 CFR Parts 730-774
- NIST Post-Quantum Cryptography: https://csrc.nist.gov/projects/post-quantum-cryptography
- BIS Encryption Registration: https://www.bis.doc.gov/index.php/policy-guidance/encryption

---

**Last Updated**: 2025-01-14

**IMPORTANT**: This software is subject to US export control regulations. Unauthorized export or transfer is prohibited.
