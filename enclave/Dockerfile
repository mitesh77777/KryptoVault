###############################################################################
# Enclave-Guard – Nitro Enclave Dockerfile
#
# This Dockerfile builds the enclave image (EIF) that runs inside the
# AWS Nitro Enclave. The resulting image contains only the Python signing
# service and its minimal dependencies.
#
# Build with:
#   nitro-cli build-enclave --docker-dir ./enclave --docker-uri enclave-guard:latest --output-file enclave-guard.eif
###############################################################################

# ── Stage 1: Builder ────────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /app

# Install build dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir \
        cryptography==42.0.5 \
        cbor2==5.6.2 \
        requests==2.31.0 \
        boto3==1.34.69

# Copy application source
COPY src/ /app/

# ── Stage 2: Runtime ────────────────────────────────────────────────────────
FROM python:3.11-slim

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /app /app

# Enclave runs as non-root
RUN useradd -r -s /bin/false enclaveuser
USER enclaveuser

# The enclave communicates via vsock (no network)
# Port 5000 on CID 16 (enclave CID)
EXPOSE 5000

# Health check label
LABEL maintainer="enclave-guard" \
      description="Nitro Enclave signing service for Hedera transactions" \
      version="1.0.0"

ENTRYPOINT ["python3", "/app/server.py"]
