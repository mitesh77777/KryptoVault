///////////////////////////////////////////////////////////////////////////////
// Enclave-Guard – Vsock Client
//
// Communicates with the signing service running inside the Nitro Enclave
// over a vsock (VM socket) connection.
///////////////////////////////////////////////////////////////////////////////

const net = require("net");

// AF_VSOCK is not natively supported in Node.js; on EC2 with Nitro Enclaves,
// we use the `vsock` npm package or a unix-socket shim. For portability,
// we implement a simple TCP-based mock that can be swapped for real vsock.

/**
 * Send a signing request to the Nitro Enclave via vsock.
 *
 * @param {number} cid  - The enclave CID (typically 16)
 * @param {number} port - The enclave vsock port (typically 5000)
 * @param {object} request - The request payload
 * @returns {Promise<object>} The response from the enclave
 */
async function sendToEnclave(cid, port, request) {
  return new Promise((resolve, reject) => {
    // In production on a Nitro Enclave host, this uses AF_VSOCK.
    // The vsock connection is established via /dev/vsock using the
    // `vsock` Node.js native addon or a C++ binding.
    //
    // For the hackathon, we use the vsock-node helper which wraps
    // the Linux vsock syscall.

    let vsockConnect;
    try {
      // Try loading the native vsock module (available on EC2)
      const vsock = require("vsock");
      vsockConnect = () => vsock.connect(cid, port);
    } catch {
      // Fallback: use a unix socket for local development/testing
      console.warn(
        "[vsock] Native vsock not available, using localhost TCP fallback",
      );
      vsockConnect = () => net.connect({ host: "127.0.0.1", port });
    }

    const conn = vsockConnect();
    const chunks = [];

    conn.on("connect", () => {
      // Send length-prefixed JSON message (matching Python server protocol)
      const payload = Buffer.from(JSON.stringify(request), "utf-8");
      const header = Buffer.alloc(4);
      header.writeUInt32BE(payload.length, 0);
      conn.write(Buffer.concat([header, payload]));
    });

    conn.on("data", (chunk) => {
      chunks.push(chunk);
    });

    conn.on("end", () => {
      try {
        const data = Buffer.concat(chunks);
        // Skip 4-byte length header
        const jsonBuf = data.length > 4 ? data.slice(4) : data;
        const response = JSON.parse(jsonBuf.toString("utf-8"));
        resolve(response);
      } catch (err) {
        reject(new Error(`Failed to parse enclave response: ${err.message}`));
      }
    });

    conn.on("error", (err) => {
      reject(new Error(`Vsock connection error: ${err.message}`));
    });

    // Timeout after 30 seconds
    conn.setTimeout(30000, () => {
      conn.destroy();
      reject(new Error("Vsock connection timed out"));
    });
  });
}

/**
 * Request the enclave to sign a transaction hash.
 *
 * @param {number} cid - Enclave CID
 * @param {number} port - Enclave port
 * @param {Buffer} messageHash - SHA-256 hash of the transaction bytes
 * @param {string} keyId - KMS key ID or alias
 * @param {string} region - AWS region
 * @returns {Promise<Buffer>} DER-encoded ECDSA signature
 */
async function requestEnclaveSign(cid, port, messageHash, keyId, region) {
  const response = await sendToEnclave(cid, port, {
    action: "sign",
    key_id: keyId,
    message: messageHash.toString("hex"),
    region: region,
  });

  if (response.status !== "success") {
    throw new Error(`Enclave signing failed: ${response.error}`);
  }

  return Buffer.from(response.signature, "hex");
}

/**
 * Health check the enclave.
 */
async function enclaveHealthCheck(cid, port) {
  const response = await sendToEnclave(cid, port, { action: "health" });
  return response;
}

module.exports = { sendToEnclave, requestEnclaveSign, enclaveHealthCheck };
