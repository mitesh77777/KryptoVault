///////////////////////////////////////////////////////////////////////////////
// Enclave-Guard – Configuration
//
// Loads environment variables and provides typed config object.
///////////////////////////////////////////////////////////////////////////////

require("dotenv").config();

const config = {
  // AWS
  aws: {
    region: process.env.AWS_REGION || "us-east-1",
    kmsKeyId: process.env.KMS_KEY_ID || "alias/enclave-guard-secp256k1",
  },

  // Hedera
  hedera: {
    network: process.env.HEDERA_NETWORK || "testnet",
    operatorId: process.env.HEDERA_OPERATOR_ID,
    operatorKey: process.env.HEDERA_OPERATOR_KEY,
    targetAccount: process.env.HEDERA_TARGET_ACCOUNT,
    transferAmount: parseInt(process.env.TRANSFER_AMOUNT || "100000000", 10),
  },

  // Enclave vsock
  enclave: {
    cid: parseInt(process.env.ENCLAVE_CID || "16", 10),
    port: parseInt(process.env.ENCLAVE_PORT || "5000", 10),
  },
};

// Validation
function validateConfig() {
  const required = [
    ["HEDERA_OPERATOR_ID", config.hedera.operatorId],
    ["HEDERA_OPERATOR_KEY", config.hedera.operatorKey],
  ];

  const missing = required.filter(([, val]) => !val);
  if (missing.length > 0) {
    throw new Error(
      `Missing required environment variables: ${missing.map(([k]) => k).join(", ")}`,
    );
  }
}

module.exports = { config, validateConfig };
