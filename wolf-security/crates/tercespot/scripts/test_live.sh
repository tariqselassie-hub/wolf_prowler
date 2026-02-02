#!/bin/bash
set -e

echo "Building Docker Test Image..."
docker build -f Dockerfile.test -t tersec-live-test .

echo "Running Live Test Container..."
docker run --rm tersec-live-test
