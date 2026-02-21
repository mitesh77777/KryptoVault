###############################################################################
# Enclave-Guard – Nitro Enclave Signing Server
#
# This service runs INSIDE the Nitro Enclave and:
#   1. Listens on a vsock socket for incoming signing requests
#   2. Generates a Nitro Attestation Document with the transaction hash
#   3. Calls AWS KMS Sign via the vsock-proxy running on the parent
#   4. Returns the DER-encoded signature to the parent
#
# The enclave has NO network access – all communication goes through vsock.
###############################################################################

import json
import socket
import struct
import sys
import traceback

from kms_proxy_client import KMSProxyClient

# ── Vsock Constants ─────────────────────────────────────────────────────────
VSOCK_CID_ANY = 0xFFFFFFFF  # Listen on any CID
VSOCK_PORT = 5000            # Port the enclave listens on

# AF_VSOCK socket family constant
AF_VSOCK = 40


def create_vsock_listener():
    """Create and bind a vsock listener socket."""
    sock = socket.socket(AF_VSOCK, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((VSOCK_CID_ANY, VSOCK_PORT))
    sock.listen(5)
    print(f"[enclave] Listening on vsock port {VSOCK_PORT}", flush=True)
    return sock


def recv_message(conn):
    """Receive a length-prefixed JSON message from the parent."""
    # Read 4-byte length header (big-endian)
    raw_len = conn.recv(4)
    if not raw_len or len(raw_len) < 4:
        return None
    msg_len = struct.unpack(">I", raw_len)[0]

    # Read the full message
    data = b""
    while len(data) < msg_len:
        chunk = conn.recv(min(msg_len - len(data), 4096))
        if not chunk:
            return None
        data += chunk

    return json.loads(data.decode("utf-8"))


def send_message(conn, msg):
    """Send a length-prefixed JSON message to the parent."""
    payload = json.dumps(msg).encode("utf-8")
    conn.sendall(struct.pack(">I", len(payload)) + payload)


def handle_sign_request(kms_client, request):
    """
    Handle a signing request from the parent instance.

    Expected request format:
    {
        "action": "sign",
        "key_id": "alias/enclave-guard-secp256k1",
        "message": "<hex-encoded transaction hash>",
        "region": "us-east-1"
    }

    Returns:
    {
        "status": "success",
        "signature": "<hex-encoded DER signature>"
    }
    """
    key_id = request.get("key_id", "alias/enclave-guard-secp256k1")
    message_hex = request.get("message")
    region = request.get("region", "us-east-1")

    if not message_hex:
        return {"status": "error", "error": "Missing 'message' field"}

    try:
        message_bytes = bytes.fromhex(message_hex)
    except ValueError:
        return {"status": "error", "error": "Invalid hex in 'message' field"}

    print(f"[enclave] Signing {len(message_bytes)}-byte message with key {key_id}", flush=True)

    try:
        # Generate attestation document and sign via KMS
        signature = kms_client.sign_with_attestation(
            key_id=key_id,
            message=message_bytes,
            region=region,
        )

        return {
            "status": "success",
            "signature": signature.hex(),
        }

    except Exception as e:
        print(f"[enclave] Signing error: {e}", flush=True)
        traceback.print_exc()
        return {"status": "error", "error": str(e)}


def handle_health_request():
    """Handle a health check request."""
    return {
        "status": "success",
        "service": "enclave-guard",
        "version": "1.0.0",
    }


def main():
    """Main enclave server loop."""
    print("[enclave] ══════════════════════════════════════════", flush=True)
    print("[enclave]  Enclave-Guard Signing Service v1.0.0", flush=True)
    print("[enclave]  Nitro Enclave – Hedera Transaction Signer", flush=True)
    print("[enclave] ══════════════════════════════════════════", flush=True)

    # Initialize KMS proxy client (communicates via vsock to parent's vsock-proxy)
    kms_client = KMSProxyClient(
        vsock_proxy_cid=3,       # Parent instance CID
        vsock_proxy_port=8000,   # vsock-proxy port on parent
    )

    # Create vsock listener
    listener = create_vsock_listener()

    while True:
        try:
            conn, addr = listener.accept()
            print(f"[enclave] Connection from CID={addr[0]} Port={addr[1]}", flush=True)

            try:
                request = recv_message(conn)
                if request is None:
                    print("[enclave] Empty request, closing connection", flush=True)
                    conn.close()
                    continue

                action = request.get("action", "")
                print(f"[enclave] Action: {action}", flush=True)

                if action == "sign":
                    response = handle_sign_request(kms_client, request)
                elif action == "health":
                    response = handle_health_request()
                else:
                    response = {"status": "error", "error": f"Unknown action: {action}"}

                send_message(conn, response)

            except Exception as e:
                print(f"[enclave] Handler error: {e}", flush=True)
                traceback.print_exc()
                try:
                    send_message(conn, {"status": "error", "error": str(e)})
                except Exception:
                    pass
            finally:
                conn.close()

        except KeyboardInterrupt:
            print("[enclave] Shutting down...", flush=True)
            break
        except Exception as e:
            print(f"[enclave] Accept error: {e}", flush=True)
            traceback.print_exc()

    listener.close()


if __name__ == "__main__":
    main()
