"""
Enclave-Guard: KMS Proxy Client
================================
Handles communication with AWS KMS through the vsock-proxy running
on the parent instance. Inside the enclave, there is no direct
network access – all HTTPS calls must be proxied via vsock.
"""

import json
import socket
import ssl
import struct
import base64
from typing import Optional

# vsock-proxy on parent typically listens on port 8443
# and forwards to kms.<region>.amazonaws.com:443
PROXY_CID  = 3      # Parent CID
PROXY_PORT = 8443   # vsock-proxy port


def call_kms_via_proxy(
    region: str,
    key_id: str,
    message: bytes,
    attestation_document: bytes,
    signing_algorithm: str = "ECDSA_SHA_256"
) -> dict:
    """
    Make a KMS Sign API call through the vsock-proxy.

    The vsock-proxy on the parent translates vsock connections
    to HTTPS connections to the KMS endpoint.
    """
    # Build the KMS API request body
    body = json.dumps({
        "KeyId": key_id,
        "Message": base64.b64encode(message).decode(),
        "MessageType": "DIGEST",
        "SigningAlgorithm": signing_algorithm,
        "Recipient": {
            "AttestationDocument": base64.b64encode(attestation_document).decode(),
            "KeyEncryptionAlgorithm": "RSAES_OAEP_SHA_256"
        }
    })

    # Build the HTTP request
    host = f"kms.{region}.amazonaws.com"
    http_request = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-amz-json-1.1\r\n"
        f"X-Amz-Target: TrentService.Sign\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"\r\n"
        f"{body}"
    )

    # Connect through vsock-proxy
    sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    sock.connect((PROXY_CID, PROXY_PORT))

    # Wrap in TLS
    context = ssl.create_default_context()
    ssock = context.wrap_socket(sock, server_hostname=host)

    try:
        ssock.sendall(http_request.encode())

        # Read response
        response = b""
        while True:
            chunk = ssock.recv(4096)
            if not chunk:
                break
            response += chunk

        # Parse HTTP response
        header_end = response.find(b"\r\n\r\n")
        if header_end == -1:
            raise RuntimeError("Invalid HTTP response from KMS proxy")

        response_body = response[header_end + 4:]
        result = json.loads(response_body)
        return result

    finally:
        ssock.close()


def call_kms_get_public_key(
    region: str,
    key_id: str,
    attestation_document: Optional[bytes] = None
) -> dict:
    """
    Get the public key from KMS through the vsock-proxy.
    """
    body = json.dumps({"KeyId": key_id})

    host = f"kms.{region}.amazonaws.com"
    http_request = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-amz-json-1.1\r\n"
        f"X-Amz-Target: TrentService.GetPublicKey\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"\r\n"
        f"{body}"
    )

    sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    sock.connect((PROXY_CID, PROXY_PORT))

    context = ssl.create_default_context()
    ssock = context.wrap_socket(sock, server_hostname=host)

    try:
        ssock.sendall(http_request.encode())

        response = b""
        while True:
            chunk = ssock.recv(4096)
            if not chunk:
                break
            response += chunk

        header_end = response.find(b"\r\n\r\n")
        response_body = response[header_end + 4:]
        return json.loads(response_body)

    finally:
        ssock.close()
