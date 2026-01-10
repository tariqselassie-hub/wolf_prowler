# Compliance & Auditing

Automated tools to ensure your infrastructure meets industry standards, specifically aligned with **NIST SP 800-53 Rev. 5**.

## NIST SP 800-53 Implementation

Wolf Prowler includes specific features designed to address federal compliance controls.

### 1. Configuration Management (CM-3)
*   **Feature**: `ConfigurationMonitor`
*   **Description**: A dedicated background service that monitors critical configuration files (e.g., `settings.toml`) for unauthorized changes.
*   **Mechanism**: Computes SHA-256 checksums at startup and periodically verifies file integrity. Unauthorized modifications trigger a High-severity `PolicyViolation` alert.

### 2. Access Control (AC-12)
*   **Feature**: Enhanced Session Termination
*   **Description**: Strict enforcement of session lifecycles to prevent unauthorized access via idle sessions.
*   **Controls**:
    *   **Idle Timeout**: Configurable inactivity timer (default 30 minutes).
    *   **Force Termination**: Administrative capability to immediately revoke specific sessions, logging the rationale for the audit trail.

### 3. System Integrity (SI-7)
*   **Feature**: Runtime Integrity Validation
*   **Description**: Automated verification of the running software against its Software Bill of Materials (SBOM).
*   **Mechanism**: On startup, the system checks for the presence of a valid `sbom.json` to ensure the deployed binary matches the expected build artifacts.

### 4. Identification and Authentication (IA-2)
*   **Feature**: Federal ID Integration Hooks
*   **Description**: Architecture supports integration with Federal PIV/CAC authentication.
*   **Mechanism**: The `IdentityProviderManager` includes validation logic for Smart Card-based X.509 certificate chains, ready for integration with hardware tokens.

### 5. Boundary Protection (SC-7)
*   **Feature**: Secure Proxying
*   **Description**: All external threat intelligence feeds (NVD, VirusTotal) are routed through a configurable HTTP proxy.
*   **Mechanism**: Prevents direct internet access from the core security engine, ensuring all outbound traffic traverses the organization's security boundary.

## Auditing Tools

- **X509 Parsing**: Deep inspection of certificates for expiration and configuration errors.
- **ISO8601 Compliance**: Standardized temporal data handling for audit logs.
- **Git Integration**: DevSecOps auditing of repository state and changes.

## Reporting

- **Advanced Reporting**: Database-backed analytics for long-term trend analysis.
- **PDF Generation**: Automated compliance reports using `printpdf` and `genpdf`.
- **Visualization**: Integration with `plotly` and `plotters` for graphical security reports.