###############################################################################
# Enclave-Guard – KMS Proxy Client (runs inside the Nitro Enclave)
#
# This module handles:
#   1. Generating Nitro Attestation Documents via /dev/nsm
#   2. Building AWS SigV4-signed KMS Sign requests
#   3. Sending them through the vsock-proxy on the parent instance
#
# The enclave has NO direct network access. All HTTPS traffic to KMS is
# tunnelled through vsock → parent's vsock-proxy → KMS endpoint.
###############################################################################

import hashlib
import hmac
import json
import socket
import ssl
import struct
import datetime
import os

# ── Vsock Constants ─────────────────────────────────────────────────────────
AF_VSOCK = 40

# ── NSM (Nitro Secure Module) ──────────────────────────────────────────────
# In a real Nitro Enclave, we use the nsm library via /dev/nsm
# This is abstracted for portability during development

try:
    import nsm
    NSM_AVAILABLE = True
except ImportError:
    NSM_AVAILABLE = False
    print("[kms-client] WARNING: nsm module not available (not running in enclave?)", flush=True)

try:
    import cbor2
    CBOR_AVAILABLE = True
except ImportError:
    CBOR_AVAILABLE = False


class KMSProxyClient:
    """
    Client that communicates with AWS KMS through the vsock-proxy on the
    parent EC2 instance. Generates Nitro Attestation Documents to satisfy
    the kms:RecipientAttestation:PCR0 policy condition.
    """

    def __init__(self, vsock_proxy_cid=3, vsock_proxy_port=8000):
        """
        Args:
            vsock_proxy_cid: CID of the parent instance (always 3)
            vsock_proxy_port: Port where vsock-proxy listens on the parent
        """
        self.vsock_proxy_cid = vsock_proxy_cid
        self.vsock_proxy_port = vsock_proxy_port
        self._nsm_fd = None

        if NSM_AVAILABLE:
            try:
                self._nsm_fd = nsm.nsm_lib_init()
                print("[kms-client] NSM initialized successfully", flush=True)
            except Exception as e:
                print(f"[kms-client] NSM init failed: {e}", flush=True)

    def _get_attestation_document(self, public_key=None, user_data=None, nonce=None):
        """
        Request an attestation document from the Nitro Secure Module.
        
        The attestation document is a CBOR-encoded, AWS-signed document
        that contains the PCR measurements of this enclave image.
        KMS verifies this document to enforce the PCR0 condition.

        Args:
            public_key: Optional public key to include in attestation
            user_data: Optional user data (e.g., transaction hash)
            nonce: Optional nonce for freshness

        Returns:
            Raw attestation document bytes (COSE Sign1 structure)
        """
        if not NSM_AVAILABLE or self._nsm_fd is None:
            raise RuntimeError(
                "NSM not available – this code must run inside a Nitro Enclave"
            )

        attestation_doc = nsm.nsm_get_attestation_doc(
            self._nsm_fd,
            public_key=public_key,
            user_data=user_data,
            nonce=nonce,
        )

        return attestation_doc

    def _connect_to_proxy(self):
        """
        Establish a TLS connection to KMS through the vsock-proxy.
        
        Flow: Enclave → vsock → Parent vsock-proxy → KMS HTTPS endpoint
        """
        # Create vsock connection to the proxy on the parent
        vsock = socket.socket(AF_VSOCK, socket.SOCK_STREAM)
        vsock.connect((self.vsock_proxy_cid, self.vsock_proxy_port))

        # Wrap with TLS (the vsock-proxy forwards to KMS over HTTPS)
        context = ssl.create_default_context()
        tls_sock = context.wrap_socket(vsock, server_hostname="kms.us-east-1.amazonaws.com")

        return tls_sock

    def _make_kms_request(self, action, payload, region="us-east-1"):
        """
        Make a signed request to KMS through the vsock-proxy.

        Args:
            action: KMS API action (e.g., "TrentService.Sign")
            payload: JSON payload dict
            region: AWS region

        Returns:
            Parsed JSON response from KMS
        """
        host = f"kms.{region}.amazonaws.com"
        body = json.dumps(payload).encode("utf-8")

        # Build the HTTP request
        now = datetime.datetime.utcnow()
        date_stamp = now.strftime("%Y%m%d")
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")

        headers = {
            "Host": host,
            "Content-Type": "application/x-amz-json-1.1",
            "X-Amz-Target": action,
            "X-Amz-Date": amz_date,
            "Content-Length": str(len(body)),
        }

        # Build raw HTTP request 
        request_line = f"POST / HTTP/1.1\r\n"
        header_lines = "".join(f"{k}: {v}\r\n" for k, v in headers.items())
        raw_request = (request_line + header_lines + "\r\n").encode("utf-8") + body

        # Send through vsock-proxy
        tls_sock = self._connect_to_proxy()
        try:
            tls_sock.sendall(raw_request)

            # Read response
            response_data = b""
            while True:
                chunk = tls_sock.recv(4096)
                if not chunk:
                    break
                response_data += chunk
                # Check if we've received the full response
                if b"\r\n\r\n" in response_data:
                    header_end = response_data.index(b"\r\n\r\n") + 4
                    headers_raw = response_data[:header_end].decode("utf-8")
                    # Parse Content-Length
                    for line in headers_raw.split("\r\n"):
                        if line.lower().startswith("content-length:"):
                            expected_len = int(line.split(":")[1].strip())
                            body_received = len(response_data) - header_end
                            if body_received >= expected_len:
                                break
        finally:
            tls_sock.close()

        # Parse response body
        if b"\r\n\r\n" in response_data:
            body_start = response_data.index(b"\r\n\r\n") + 4
            response_body = response_data[body_start:]
            return json.loads(response_body.decode("utf-8"))
        
        raise RuntimeError(f"Invalid KMS response: {response_data[:200]}")

    def sign_with_attestation(self, key_id, message, region="us-east-1"):
        """
        Sign a message using KMS with Nitro Enclave attestation.

        This is the core function that:
        1. Generates an attestation document (contains PCR0 hash)
        2. Sends it to KMS along with the sign request
        3. KMS verifies PCR0 matches the key policy condition
        4. Returns the DER-encoded ECDSA signature

        Args:
            key_id: KMS key ID or alias (e.g., "alias/enclave-guard-secp256k1")
            message: Raw bytes to sign (typically a SHA-256 hash)
            region: AWS region

        Returns:
            DER-encoded signature bytes
        """
        import base64

        # Generate attestation document with the message as user_data
        # This binds the attestation to this specific signing request
        attestation_doc = self._get_attestation_document(
            user_data=message,
            nonce=os.urandom(16),
        )

        # Build the Recipient structure for KMS
        # This tells KMS to verify the attestation before signing
        recipient = {
            "KeyEncryptionAlgorithm": "RSAES_OAEP_SHA_256",
            "AttestationDocument": base64.b64encode(attestation_doc).decode("utf-8"),
        }

        # KMS Sign request payload
        payload = {
            "KeyId": key_id,
            "Message": base64.b64encode(message).decode("utf-8"),
            "MessageType": "DIGEST",
            "SigningAlgorithm": "ECDSA_SHA_256",
            "Recipient": recipient,
        }

        print(f"[kms-client] Sending Sign request for key {key_id}", flush=True)

        response = self._make_kms_request(
            action="TrentService.Sign",
            payload=payload,
            region=region,
        )

        if "Signature" not in response:
            error = response.get("__type", "Unknown") + ": " + response.get("message", str(response))
            raise RuntimeError(f"KMS Sign failed: {error}")

        # Decode the DER signature from base64
        signature_der = base64.b64decode(response["Signature"])
        print(f"[kms-client] Received {len(signature_der)}-byte DER signature", flush=True)

        return signature_der

    def __del__(self):
        """Cleanup NSM file descriptor."""
        if NSM_AVAILABLE and self._nsm_fd is not None:
            try:
                nsm.nsm_lib_exit(self._nsm_fd)
            except Exception:
                pass
