# ──────────────────────────────────────────────────────────────
# Enclave-Guard: Nitro Enclave Docker Image
# ──────────────────────────────────────────────────────────────
# This Dockerfile builds the enclave image that will be converted
# to an EIF (Enclave Image File) using nitro-cli.
#
# Build:
#   docker build -t enclave-guard-enclave .
#   nitro-cli build-enclave --docker-uri enclave-guard-enclave:latest \
#       --output-file enclave-guard.eif
#
# The PCR0 hash from the build output must be set in the KMS
# key policy to enable attestation-based access control.
# ──────────────────────────────────────────────────────────────

FROM python:3.11-slim

# Install minimal dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy application code
COPY src/ /app/

# The enclave runs the signing server
CMD ["python3", "/app/server.py"]
