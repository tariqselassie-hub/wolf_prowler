# Clean Architecture Dependency Audit

**Date:** December 23, 2025
**Auditor:** Gemini Code Assist

## 1. Audit Goal

Verify that the `wolfsec` crate adheres to the Clean Architecture dependency rule: **Dependencies must only point inwards.**

- **Domain Layer:** Must NOT depend on Application or Infrastructure layers.
- **Application Layer:** May depend on Domain, but NOT on Infrastructure.
- **Infrastructure Layer:** May depend on both Application and Domain.

## 2. Audit Findings (`Alert` Vertical Slice)

The newly refactored modules for `Alert` management (`domain`, `application`, `infrastructure`) were audited.

### Domain Layer (`wolfsec/src/domain/`)
- **`entities`**: **✅ PASS.** Contains only pure Rust structs and standard library types. No `sqlx` or `axum` dependencies.
- **`repositories`**: **✅ PASS.** Defines `async-trait` traits. No infrastructure dependencies.
- **`services`**: **✅ PASS.** Depends only on repository traits and domain entities.

**Conclusion:** The Domain layer is clean and correctly isolated.

### Application Layer (`wolfsec/src/application/`)
- **`commands` & `queries`**: **✅ PASS.** Handlers depend on `Arc<dyn AlertRepository>` (the domain trait), not the concrete `PostgresAlertRepository`.
- **`dtos`**: **✅ PASS.** DTOs are used for data transfer, correctly converting from domain entities.
- **`error`**: **✅ PASS.** Application-level errors correctly wrap domain errors.

**Conclusion:** The Application layer correctly orchestrates use cases without depending on infrastructure details.

### Infrastructure Layer (`wolfsec/src/infrastructure/`)
- **`persistence`**: **✅ PASS.** The `PostgresAlertRepository` correctly implements the `domain::repositories::AlertRepository` trait and uses `sqlx` for database operations.

**Conclusion:** The Infrastructure layer correctly implements the ports defined by the domain.

## 3. Action Items: Legacy Module Refactoring

The audit reveals that modules outside the new `domain/`, `application/`, and `infrastructure/` structure still contain mixed concerns.

**Next Steps:**
- [ ] **Refactor `wolfsec/src/monitoring`**: Separate monitoring logic (domain), alert generation (application), and notification sending (infrastructure).
- [ ] **Refactor `wolfsec/src/authentication`**: Isolate user/role entities (domain), authentication use cases (application), and password hashing/storage (infrastructure).
- [ ] **Refactor `wolfsec/src/crypto`**: This module is complex. It should be evaluated to see if it can be treated as a pure infrastructure-level utility or if it contains domain concepts that need to be extracted.
- [ ] **Continue this pattern** for all other modules (`reputation`, `threat_detection`, etc.).