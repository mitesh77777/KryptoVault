///////////////////////////////////////////////////////////////////////////////
// Enclave-Guard – KMS Signer for Hedera SDK
//
// Custom signer that:
//   1. Fetches the public key from AWS KMS (secp256k1)
//   2. Sends transaction bytes to the Nitro Enclave for signing
//   3. Strips ASN.1 DER encoding → raw 64-byte (r || s) signature
//
// Compatible with @hashgraph/sdk v2.54.0
///////////////////////////////////////////////////////////////////////////////

const { PublicKey } = require("@hashgraph/sdk");
const { KMSClient, GetPublicKeyCommand } = require("@aws-sdk/client-kms");
const crypto = require("crypto");
const { requestEnclaveSign } = require("./vsock/client");
const { config } = require("./config");

class KMSSigner {
  /**
   * @param {object} opts
   * @param {string} opts.keyId       - KMS key ID or alias
   * @param {string} opts.region      - AWS region
   * @param {number} opts.enclaveCid  - Enclave CID for vsock
   * @param {number} opts.enclavePort - Enclave vsock port
   */
  constructor(opts = {}) {
    this.keyId = opts.keyId || config.aws.kmsKeyId;
    this.region = opts.region || config.aws.region;
    this.enclaveCid = opts.enclaveCid || config.enclave.cid;
    this.enclavePort = opts.enclavePort || config.enclave.port;

    this._kmsClient = new KMSClient({ region: this.region });
    this._publicKey = null;    // Cached Hedera PublicKey
    this._publicKeyDer = null; // Cached raw DER bytes
  }

  /**
   * Fetch the public key from KMS and return a Hedera-compatible PublicKey.
   *
   * KMS returns the public key in DER-encoded SubjectPublicKeyInfo format.
   * We extract the raw 33-byte compressed secp256k1 point for Hedera.
   *
   * @returns {Promise<PublicKey>}
   */
  async getPublicKey() {
    if (this._publicKey) {
      return this._publicKey;
    }

    console.log(`[KMSSigner] Fetching public key from KMS: ${this.keyId}`);

    const command = new GetPublicKeyCommand({ KeyId: this.keyId });
    const response = await this._kmsClient.send(command);

    // response.PublicKey is a Uint8Array in DER (SubjectPublicKeyInfo) format
    const derBytes = Buffer.from(response.PublicKey);
    this._publicKeyDer = derBytes;

    // Extract the raw EC point from the DER structure
    // SubjectPublicKeyInfo for secp256k1:
    //   SEQUENCE {
    //     SEQUENCE { OID ecPublicKey, OID secp256k1 }
    //     BIT STRING (0x04 || x || y)  -- uncompressed point
    //   }
    const rawPoint = extractECPointFromDER(derBytes);

    // Compress the point (Hedera uses compressed secp256k1 keys)
    const compressedKey = compressECPoint(rawPoint);

    // Create Hedera ECDSA secp256k1 PublicKey from compressed bytes
    this._publicKey = PublicKey.fromBytesECDSA(compressedKey);

    console.log(
      `[KMSSigner] Public key loaded: ${this._publicKey.toStringRaw()}`,
    );

    return this._publicKey;
  }

  /**
   * Sign a message by sending it to the Nitro Enclave.
   *
   * The Enclave generates an Attestation Document, calls KMS Sign via
   * vsock-proxy, and returns the DER-encoded ECDSA signature.
   *
   * We then strip the ASN.1 DER wrapper to get raw (r || s) 64 bytes
   * that the Hedera network expects.
   *
   * @param {Uint8Array} message - The raw transaction bytes to sign
   * @returns {Promise<Uint8Array>} 64-byte raw ECDSA signature (r || s)
   */
  async sign(message) {
    // Hash the message (KMS expects a pre-hashed digest for ECDSA_SHA_256)
    const messageHash = crypto.createHash("sha256").update(message).digest();

    console.log(
      `[KMSSigner] Requesting enclave signature for ${messageHash.length}-byte digest`,
    );

    // Send to enclave for signing
    const derSignature = await requestEnclaveSign(
      this.enclaveCid,
      this.enclavePort,
      messageHash,
      this.keyId,
      this.region,
    );

    // Strip ASN.1 DER encoding → raw 64-byte (r || s)
    const rawSignature = derToRawSignature(derSignature);

    console.log(
      `[KMSSigner] Received ${rawSignature.length}-byte raw signature`,
    );

    return rawSignature;
  }

  /**
   * Get the Hedera AccountId associated with this KMS key.
   * Must be called after the account is created on-chain with this public key.
   */
  async getAccountId() {
    const pubKey = await this.getPublicKey();
    return pubKey.toAccountId(0, 0);
  }
}

///////////////////////////////////////////////////////////////////////////////
// ASN.1 / DER Helpers
///////////////////////////////////////////////////////////////////////////////

/**
 * Extract the raw EC point (uncompressed, 65 bytes) from a DER-encoded
 * SubjectPublicKeyInfo structure.
 *
 * @param {Buffer} der - DER-encoded SubjectPublicKeyInfo
 * @returns {Buffer} Raw uncompressed EC point (0x04 || x || y)
 */
function extractECPointFromDER(der) {
  // The BIT STRING containing the EC point is the last element.
  // For secp256k1, the SubjectPublicKeyInfo is typically 88 bytes:
  //   30 56 30 10 06 07 2a 86 48 ce 3d 02 01 06 05 2b 81 04 00 0a
  //   03 42 00 04 <x: 32 bytes> <y: 32 bytes>
  //
  // We search for the BIT STRING tag (0x03) followed by the point.

  let offset = 0;

  // Skip outer SEQUENCE tag + length
  if (der[offset] !== 0x30) {
    throw new Error("Expected SEQUENCE tag in SubjectPublicKeyInfo");
  }
  offset += 1;
  offset += derReadLengthBytes(der, offset);

  // Skip inner SEQUENCE (algorithm identifier)
  if (der[offset] !== 0x30) {
    throw new Error("Expected SEQUENCE tag in AlgorithmIdentifier");
  }
  offset += 1;
  const algoLen = derReadLength(der, offset);
  offset += derReadLengthBytes(der, offset) + algoLen;

  // Read BIT STRING
  if (der[offset] !== 0x03) {
    throw new Error("Expected BIT STRING tag for public key");
  }
  offset += 1;
  const bitStringLen = derReadLength(der, offset);
  offset += derReadLengthBytes(der, offset);

  // Skip the "unused bits" byte (should be 0x00)
  const unusedBits = der[offset];
  offset += 1;

  // The remaining bytes are the EC point
  const pointLen = bitStringLen - 1; // minus unused-bits byte
  const point = der.slice(offset, offset + pointLen);

  if (point[0] !== 0x04 || point.length !== 65) {
    throw new Error(
      `Unexpected EC point format: prefix=0x${point[0].toString(16)}, len=${point.length}`,
    );
  }

  return point;
}

/**
 * Compress an uncompressed secp256k1 EC point (65 bytes → 33 bytes).
 *
 * @param {Buffer} uncompressed - 0x04 || x (32 bytes) || y (32 bytes)
 * @returns {Buffer} 0x02/0x03 || x (32 bytes)
 */
function compressECPoint(uncompressed) {
  if (uncompressed[0] !== 0x04 || uncompressed.length !== 65) {
    throw new Error("Expected uncompressed EC point (65 bytes starting with 0x04)");
  }

  const x = uncompressed.slice(1, 33);
  const y = uncompressed.slice(33, 65);

  // If y is even → prefix 0x02, if odd → prefix 0x03
  const prefix = y[31] % 2 === 0 ? 0x02 : 0x03;

  return Buffer.concat([Buffer.from([prefix]), x]);
}

/**
 * Convert an ASN.1 DER-encoded ECDSA signature to raw 64-byte format.
 *
 * DER format:
 *   SEQUENCE {
 *     INTEGER r (variable length, up to 33 bytes with leading 0x00)
 *     INTEGER s (variable length, up to 33 bytes with leading 0x00)
 *   }
 *
 * Raw format: r (32 bytes, zero-padded) || s (32 bytes, zero-padded)
 *
 * @param {Buffer} derSig - DER-encoded ECDSA signature
 * @returns {Buffer} Raw 64-byte signature (r || s)
 */
function derToRawSignature(derSig) {
  let offset = 0;

  // SEQUENCE tag
  if (derSig[offset] !== 0x30) {
    throw new Error("Invalid DER signature: expected SEQUENCE tag");
  }
  offset += 1;

  // SEQUENCE length
  offset += derReadLengthBytes(derSig, offset);

  // Read r INTEGER
  if (derSig[offset] !== 0x02) {
    throw new Error("Invalid DER signature: expected INTEGER tag for r");
  }
  offset += 1;
  const rLen = derSig[offset];
  offset += 1;
  let r = derSig.slice(offset, offset + rLen);
  offset += rLen;

  // Read s INTEGER
  if (derSig[offset] !== 0x02) {
    throw new Error("Invalid DER signature: expected INTEGER tag for s");
  }
  offset += 1;
  const sLen = derSig[offset];
  offset += 1;
  let s = derSig.slice(offset, offset + sLen);

  // Strip leading zero bytes (DER uses them for positive sign on high-bit values)
  if (r.length > 32 && r[0] === 0x00) {
    r = r.slice(r.length - 32);
  }
  if (s.length > 32 && s[0] === 0x00) {
    s = s.slice(s.length - 32);
  }

  // Zero-pad to exactly 32 bytes each
  const rPadded = Buffer.alloc(32);
  r.copy(rPadded, 32 - r.length);

  const sPadded = Buffer.alloc(32);
  s.copy(sPadded, 32 - s.length);

  return Buffer.concat([rPadded, sPadded]);
}

///////////////////////////////////////////////////////////////////////////////
// DER Length Parsing Helpers
///////////////////////////////////////////////////////////////////////////////

/**
 * Read a DER length value at the given offset.
 * @returns {number} The length value
 */
function derReadLength(buf, offset) {
  if (buf[offset] < 0x80) {
    return buf[offset];
  }
  const numBytes = buf[offset] & 0x7f;
  let length = 0;
  for (let i = 0; i < numBytes; i++) {
    length = (length << 8) | buf[offset + 1 + i];
  }
  return length;
}

/**
 * Return the number of bytes consumed by the length field itself.
 * @returns {number}
 */
function derReadLengthBytes(buf, offset) {
  if (buf[offset] < 0x80) {
    return 1;
  }
  return 1 + (buf[offset] & 0x7f);
}

module.exports = {
  KMSSigner,
  derToRawSignature,
  extractECPointFromDER,
  compressECPoint,
};
