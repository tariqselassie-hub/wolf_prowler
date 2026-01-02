# Deployment Guide

## Docker

```bash
# Build image
docker build -t wolf-prowler .

# Run container
docker run -p 8080:8080 wolf-prowler

# With custom config
docker run -p 8080:8080 \
  -v $(pwd)/config:/app/config \
  wolf-prowler
```

## Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: wolf-prowler
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: wolf-prowler
        image: wolf-prowler:latest
```