#!/bin/bash
# This script creates the necessary directory structure for the Clean Architecture refactoring.
# Run it from the project root directory: bash scripts/setup_dirs.sh

echo "Creating directory structure for wolfsec and wolf_net..."

# Directories for wolfsec
mkdir -p wolfsec/src/domain/entities
mkdir -p wolfsec/src/domain/repositories
mkdir -p wolfsec/src/domain/services

mkdir -p wolfsec/src/application/commands/auth
mkdir -p wolfsec/src/application/commands/crypto
mkdir -p wolfsec/src/application/commands/monitoring

mkdir -p wolfsec/src/application/queries/crypto
mkdir -p wolfsec/src/application/queries/monitoring

mkdir -p wolfsec/src/application/dtos
mkdir -p wolfsec/src/application/services

mkdir -p wolfsec/src/infrastructure/persistence
mkdir -p wolfsec/src/infrastructure/services

echo "Directory structure created successfully."
