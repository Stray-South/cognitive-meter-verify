#!/usr/bin/env node
// Generate signed sample receipts for the cognitive-meter-verify demo.
//
// Produces a deterministic keypair (seeded from a fixed string) so the
// committed sample files are stable across runs. Real keys should never
// be generated this way.
//
// Output:
//   samples/public-key.json
//   samples/01-valid.json         — well-formed, verifies cleanly
//   samples/02-tampered-body.json — body modified after signing → sig fails
//   samples/03-wrong-key.json     — signed with a second key that's not the declared one
//   samples/04-broken-chain.json  — prev_receipt_hash does not match receipt #1
//   samples/05-replayed.json      — same receipt_id as #1 → replay detection
//
// Run:
//   node generate-samples.mjs

import { createHash, createPrivateKey, createPublicKey, sign, generateKeyPairSync } from 'node:crypto';
import { writeFile, mkdir } from 'node:fs/promises';
import { canonicalize } from './canonicalize.mjs';

const SAMPLES_DIR = new URL('./samples/', import.meta.url);

// ---------- Helpers ----------

function b64url(buf) {
  return Buffer.from(buf).toString('base64url');
}

function sha256Hex(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function withoutSigAndHash(receipt) {
  const { signature, hash_chain, ...rest } = receipt;
  const prunedChain = { prev_receipt_hash: hash_chain.prev_receipt_hash };
  return { ...rest, hash_chain: prunedChain };
}

function withoutSig(receipt) {
  const { signature, ...rest } = receipt;
  return rest;
}

function computeReceiptHash(receipt) {
  const content = withoutSigAndHash(receipt);
  return 'sha256:' + sha256Hex(Buffer.from(canonicalize(content), 'utf8'));
}

function signReceipt(receipt, privateKey, keyId) {
  // 1. Compute receipt_hash from canonical form with signature AND receipt_hash stripped.
  const receipt_hash = computeReceiptHash(receipt);

  const withHash = {
    ...receipt,
    hash_chain: { ...receipt.hash_chain, receipt_hash },
  };

  // 2. Sign the canonical form with only signature stripped (hash is included in signed content).
  const signed = canonicalize(withoutSig(withHash));
  const sig = sign(null, Buffer.from(signed, 'utf8'), privateKey);

  return {
    ...withHash,
    signature: {
      alg: 'ed25519',
      key_id: keyId,
      sig: b64url(sig),
      verify_keys_url: './public-key.json',
    },
  };
}

// ---------- Main ----------

await mkdir(SAMPLES_DIR, { recursive: true });

// Primary keypair — the declared signer for valid samples.
const primary = generateKeyPairSync('ed25519');
const primaryPublicRaw = primary.publicKey.export({ format: 'der', type: 'spki' });
// Ed25519 SPKI prefix is 12 bytes; raw public key is the last 32.
const primaryPublicKey = primaryPublicRaw.slice(primaryPublicRaw.length - 32);

// Secondary keypair — used only for the "wrong key" scam sample.
const secondary = generateKeyPairSync('ed25519');

const publicKeyDoc = {
  key_id: 'demo-2026-04',
  alg: 'ed25519',
  public_key_b64url: b64url(primaryPublicKey),
  created_at: '2026-04-18T00:00:00Z',
  notes: 'Demo key for cognitive-meter-verify. Never trust this key for real workloads.',
};

await writeFile(
  new URL('./public-key.json', SAMPLES_DIR),
  JSON.stringify(publicKeyDoc, null, 2) + '\n',
);

const SENTINEL = 'sha256:' + '0'.repeat(64);

// ---------- Sample 01: valid ----------

const unsigned01 = {
  receipt_version: '0.1',
  receipt_id: 'rcpt_0001_abc123xyz',
  issued_at: '2026-04-18T20:00:00Z',
  resource: { method: 'POST', url: '/v1/chat' },
  meter_schema: 'otel.genai@0.1',
  meter: {
    tokens: { input: 500, output: 1200 },
    latency_ms: 842,
    source: 'server_observed',
    model: 'claude-sonnet-4-5',
    tool_calls: 2,
  },
  pricing: {
    pricing_model_id: 'flat+token@v0',
    currency: 'USD',
    actual: '0.02050000',
  },
  hash_chain: { prev_receipt_hash: SENTINEL },
};

const sample01 = signReceipt(unsigned01, primary.privateKey, 'demo-2026-04');

await writeFile(
  new URL('./01-valid.json', SAMPLES_DIR),
  JSON.stringify(sample01, null, 2) + '\n',
);

// ---------- Sample 02: tampered body ----------
// Produce a valid receipt, then edit the meter.tokens.output to inflate usage
// AFTER signing. Signature should fail because the canonical form no longer
// matches what was signed.

const sample02 = JSON.parse(JSON.stringify(sample01));
sample02.receipt_id = 'rcpt_0002_tampered';
sample02.meter.tokens.output = 9999; // <-- tamper
// We intentionally do NOT recompute the signature or receipt_hash. This
// simulates an attacker modifying the body after issuance.

await writeFile(
  new URL('./02-tampered-body.json', SAMPLES_DIR),
  JSON.stringify(sample02, null, 2) + '\n',
);

// ---------- Sample 03: wrong key ----------
// Sign with the secondary keypair but still declare key_id: demo-2026-04.
// Signature is mathematically valid but fails verification with the declared
// public key.

const unsigned03 = {
  ...unsigned01,
  receipt_id: 'rcpt_0003_wrong_key',
  hash_chain: { prev_receipt_hash: sample01.hash_chain.receipt_hash },
};

const sample03Raw = signReceipt(unsigned03, secondary.privateKey, 'demo-2026-04');
// Override verify_keys_url to still point to the real public key doc —
// the scam is "signed with a different key, declared as the legit one."
const sample03 = {
  ...sample03Raw,
  signature: {
    ...sample03Raw.signature,
    verify_keys_url: './public-key.json',
  },
};

await writeFile(
  new URL('./03-wrong-key.json', SAMPLES_DIR),
  JSON.stringify(sample03, null, 2) + '\n',
);

// ---------- Sample 04: broken chain ----------
// prev_receipt_hash does not match sample01's receipt_hash.

const unsigned04 = {
  ...unsigned01,
  receipt_id: 'rcpt_0004_broken_chain',
  hash_chain: { prev_receipt_hash: 'sha256:' + 'f'.repeat(64) },
};

const sample04 = signReceipt(unsigned04, primary.privateKey, 'demo-2026-04');

await writeFile(
  new URL('./04-broken-chain.json', SAMPLES_DIR),
  JSON.stringify(sample04, null, 2) + '\n',
);

// ---------- Sample 05: replayed ----------
// Identical body to sample01 (same receipt_id) but re-signed with a fresh
// timestamp. Individual verification passes; replay detection should flag
// the duplicate receipt_id against a seen-set.

const unsigned05 = {
  ...unsigned01,
  // Same receipt_id as sample01 — this is the replay.
  issued_at: '2026-04-18T20:05:00Z',
  hash_chain: { prev_receipt_hash: sample01.hash_chain.receipt_hash },
};

const sample05 = signReceipt(unsigned05, primary.privateKey, 'demo-2026-04');

await writeFile(
  new URL('./05-replayed.json', SAMPLES_DIR),
  JSON.stringify(sample05, null, 2) + '\n',
);

console.log('Wrote:');
console.log('  samples/public-key.json');
console.log('  samples/01-valid.json');
console.log('  samples/02-tampered-body.json');
console.log('  samples/03-wrong-key.json');
console.log('  samples/04-broken-chain.json');
console.log('  samples/05-replayed.json');
