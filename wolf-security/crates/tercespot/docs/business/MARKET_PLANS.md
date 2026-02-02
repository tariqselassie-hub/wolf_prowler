# 🌍 TersecPot Market Adaptation Plans

This document outlines the roadmap to adapt TersecPot for three specific high-value markets. Each plan builds upon the core "Blind Command-Bus" architecture but adds specialized tooling or configuration required for that vertical.

---

## 🏛️ Plan 1: The "Four-Eyes" Vault (Fintech & Critical Infrastructure)
**Objective**: Turn Root Access into a Consensus Ceremony.
**Key Requirement**: strict M-of-N enforcement with "Key Ceremony" tooling to ensure no single person possesses total control.

### Implementation Checklist
- [ ] **Key Ceremony Tool** (`tools/ceremony_wizard.rs`)
    - [ ] Create a CLI wizard that runs on an air-gapped machine.
    - [ ] Generates $N$ distinct Keypairs (ML-DSA-44).
    - [ ] Writes each Private Key to a separate, mounted USB drive ("Officer Key").
    - [ ] Writes all Public Keys to a single `authorized_keys` archive for the Sentinel.
    - [ ] securely wipes memory after generation.
- [ ] **Daemon Adaptation: Policy Engine**
    - [ ] Enhance Sentinel to support "Named Roles" instead of just raw keys.
    - [ ] update `authorized_keys` loading to parse metadata (e.g., `key_1.pub.meta` -> "Role: CTO").
    - [ ] Configurable Policy: `REQUIRE = "Role:DevOps AND Role:ComplianceManager"`.
- [ ] **Client Adaptation: Partial Signing Flow**
    - [ ] Update `submitter` to allow "Append Signature" mode.
    - [ ] Flow: Officer A signs -> Output `.partial` file -> Officer B signs `.partial` -> Output `.signed` -> Submit.

---

## 🛡️ Plan 2: The Quantum-Proof Air Gap Bridge (Defense)
**Objective**: Secure data ingress for disconnected networks.
**Key Requirement**: The Sentinel must act as a distinct "Decontamination Airlock" that treats all USB input as hostile until verified.

### Implementation Checklist
- [ ] **Daemon Adaptation: Ephemeral Mounts**
    - [ ] Sentinel should not watch a static folder, but listen for `udev` events (USB insertion).
    - [ ] On insertion: Mount USB as **Read-Only** & **No-Exec** (`mount -o ro,noexec`).
    - [ ] Scan root of USB for `.tersec` packages.
    - [ ] If signature fails: Immediately unmount and power off USB port (via kernel syscall).
    - [ ] If signature passes: Copy command to RAM, unmount USB, then execute.
- [ ] **Hardware Pulse Integration**
    - [ ] Enforce the "Pulse Device" (Plan 4 feature) as a *separate* physical port.
    - [ ] Requirement: "Data USB" in Port A + "Identity Token" in Port B = Execution.
- [ ] **Forensic Logging**
    - [ ] Log SHA-256 hashes of all *rejected* files to a physically Write-Once-Read-Many (WORM) drive.

---

## 🏥 Plan 3: Zero-Knowledge Administration (Healthcare & GDPR)
**Objective**: managing sensitive systems without exposing patient data to admins.
**Key Requirement**: Full audit trails where the *intent* is logged encrypted, and the *content* is never revealed to the logging infrastructure.

### Implementation Checklist
- [ ] **Encrypted Audit Stream**
    - [ ] Sentinel currently decrypts and executes.
    - [ ] New feature: Before execution, re-encrypt the command with an "Auditor Public Key" (separate from the Server Key).
    - [ ] Ship this "Auditor Blob" to a central `syslog` server.
    - [ ] Result: Sysadmins can see *that* a command ran, but only the Legal/Compliance team (holding the Auditor Key) can see *what* it was.
- [ ] **"Break-Glass" Protocol**
    - [ ] Emergency mode: Allow single-signature execution IF:
        - [ ] A special "Emergency Key" is used.
        - [ ] AND an incredibly loud alert is sent to all stakeholders (SMS/PagerDuty).
- [ ] **Privacy-Preserving Client**
    - [ ] Update `submitter` CLI to strip PII (Personally Identifiable Information) from args if possible, or warn user.

---

## 📅 Execution Strategy

1.  **Phase 1**: Build the **Key Ceremony Tool** (Plan 1). This is low-hanging fruit and benefits all users.
2.  **Phase 2**: Implement **Partial Signing/Append Mode**. Essential for distributed teams (Plan 1 & 3).
3.  **Phase 3**: Develop **Encrypted Audit Stream** (Plan 3). High value for enterprise sales.
4.  **Phase 4**: Tackle **USB/Mount Logic** (Plan 2). High complexity, specific to physical appliances.
