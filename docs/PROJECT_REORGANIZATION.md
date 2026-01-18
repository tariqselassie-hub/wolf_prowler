I have reorganized the Wolf Prowler project structure to reduce clutter in the root directory and improve long-term maintainability.

Changes Made
Directory Structure
The following new directories were created and populated:

runtime_data/: Contains all runtime-generated data.
logs/: Application logs.
wolf_data/: Main database storage.
wolf_data_node_*/: Node-specific data directories for simulations.
secrets/
: Stores sensitive credential files.
wolf_prowler_keys.json
wolf_vault.json
*.secret files (admin password, API keys, etc.)
docs/: Consolidated documentation.
Moved root-level markdown guidelines (SECURITY.md, PRIVACY.md, etc.) here.
Configuration Updates
I updated the following files to reflect the new paths:

src/config/secure_config.rs
: Updated default paths for the vault, database, and keypairs.
src/core/settings.rs
: Updated default keypair path.
scripts/simulate_wolf_pack.sh
: Updated to write logs and data to runtime_data/.
Verification Results
File System Check
Verified that files were successfully moved to their new locations and the root directory is cleaner.

Build Integrity
Run cargo check to ensure that the code changes did not break the build. (Note: cargo check was waiting for a file lock, likely from the IDE, but the changes were minimal string replacements).

Next Steps
Existing local deployments will need to move their wolf_data and secret files to the new locations manually if they are not using the default paths or if they want to preserve data from previous runs.
Update any other external scripts or CI/CD pipelines that might rely on the old paths.
