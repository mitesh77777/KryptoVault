/**
 * ─────────────────────────────────────────────────────────────
 * Enclave-Guard: Configuration
 * ─────────────────────────────────────────────────────────────
 */

import dotenv from "dotenv";
dotenv.config();

const config = {
  // ── AWS ───────────────────────────────────────────────────
  aws: {
    region: process.env.AWS_REGION || "us-east-1",
    kmsKeyId: process.env.KMS_KEY_ID || "alias/enclave-guard-hedera-key",
  },

  // ── Hedera ────────────────────────────────────────────────
  hedera: {
    network: process.env.HEDERA_NETWORK || "testnet",
    operatorId: process.env.HEDERA_OPERATOR_ID || "",
    operatorKey: process.env.HEDERA_OPERATOR_KEY || "",
  },

  // ── Enclave vsock ─────────────────────────────────────────
  enclave: {
    cid: parseInt(process.env.ENCLAVE_CID || "16", 10),
    port: parseInt(process.env.ENCLAVE_PORT || "5000", 10),
  },

  // ── Server ────────────────────────────────────────────────
  server: {
    port: parseInt(process.env.PORT || "8080", 10),
    logLevel: process.env.LOG_LEVEL || "info",
  },

  // ── HCS Audit ─────────────────────────────────────────────
  hcs: {
    topicId: process.env.HCS_TOPIC_ID || "",
  },
};

export default config;
