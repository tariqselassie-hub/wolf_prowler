# Wolfsec Development Roadmap

This document outlines the strategic steps to transition `wolfsec` from a structural skeleton to a fully functional security engine.

## 📋 Phase 1: functional Reporting & Visibility

### 1. Fix Audit Reporting (High Priority) ✅
**Goal:** Enable the generation of *real* audit reports based on actual system activity, replacing current dummy placeholders.

*   **Refactor Interface:**
    *   Update `AuditReporter::generate_report` signature.
    *   **Current:** `fn generate_report(&self, type: ReportType, period: ReportPeriod) -> Result<AuditReport>`
    *   **New:** `fn generate_report(&self, events: &[AuditEvent], type: ReportType, period: ReportPeriod) -> Result<AuditReport>`
*   **Data Integration:**
    *   Modify `AuditTrailSystem::generate_report` to first query `AuditLogger` for events within the `ReportPeriod`.
    *   Pass these retrieved events to the `AuditReporter`.
*   **Format Implementation:**
    *   **JSON/CSV:** Ensure strict serialization of the passed `AuditEvent` list.
    *   **PDF:** Implement basic layout using `printpdf` (if available) or text-based rendering to list "Top 10 Critical Events" and "Event Distribution by Category".

## 🛡️ Phase 2: Security Posture & Compliance

### 2. Implement Basic Gap Analysis ✅
**Goal:** Provide actionable "Wolf Prowler" security insights by comparing current configuration against security best practices.

*   **Define Requirements:**
    *   Create a `Requirement` struct containing: `id`, `description`, `check_function`, and `severity`.
    *   Example Requirements: "MFA Enabled", "At-Rest Encryption Active", "Audit Logging Enabled".
*   **Implement Analyzer:**
    *   In `ComplianceGapAnalyzer`, create a registry of these requirements.
    *   Implement `analyze_config(config: &SecurityConfig) -> Vec<GapFinding>`.
    *   Iterate through requirements and validate against the provided configuration.
*   **Output:**
    *   Return a list of `GapFinding`s (missing controls) with recommendations.

## ⚙️ Phase 3: DevSecOps & Pipeline Scanning

### 3. Flesh out CI/CD Security ✅
**Goal:** Enable "Prowler" capabilities to scan development pipelines for storage of secrets and insecure configurations.

*   **Pipeline Scanning:**
    *   In `CICDSecurityManager`, implement `scan_pipeline_config(content: &str) -> Vec<SecurityIssue>`.
*   **Pattern Matching:**
    *   **Secrets:** Regex scan for keys (e.g., `AWS_ACCESS_KEY`, `BEGIN RSA PRIVATE KEY`, `password: `).
    *   **Misconfiguration:** Scan for dangerous flags (e.g., `docker run --privileged`, `permitRootLogin yes`).
*   **Status Reporting:**
    *   Return a `SecurityIssue` struct with line number, severity, and remediation advice.

## 🐺 Phase 4: Wolf Pack Semantic Integration

### 4. Integrate Wolf Pack Semantics ✅
**Goal:** Unify the unique "Wolf Pack" identity/hierarchy module with standard RBAC security controls.

*   **Rank Mapping:**
    *   Map `wolf_pack::hierarchy::WolfRank` to `wolfsec::authentication::Role`.
    *   **Alpha** -> `Admin / SuperUser`
    *   **Beta** -> `Moderator / SecurityOfficer`
    *   **Delta** -> `User / Member`
    *   **Omega** -> `Guest / ReadOnly`
*   **Territory Control:**
    *   Update `wolfsec::authorization` to check `wolf_pack::territory` assignments.
    *   Ensure a user can only modify resources within their assigned "Territory" (Namespace/ResourceGroup).
*   **Implementation:**
    *   Add `get_effective_permissions(rank: WolfRank)` to the `AuthManager`.
