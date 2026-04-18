#!/usr/bin/env node
// Round-trip test: verify each generated sample behaves as expected.
// Exits non-zero if any sample misbehaves.

import { readFile } from 'node:fs/promises';
import { createPublicKey, verify, createHash } from 'node:crypto';
import { canonicalize } from './canonicalize.mjs';

function b64urlDecode(s) {
  const pad = '='.repeat((4 - (s.length % 4)) % 4);
  return Buffer.from((s + pad).replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

function withoutSig(r) { const { signature, ...rest } = r; return rest; }
function withoutSigAndHash(r) {
  const { signature, hash_chain, ...rest } = r;
  return { ...rest, hash_chain: { prev_receipt_hash: hash_chain.prev_receipt_hash } };
}

function sha256Hex(str) {
  return createHash('sha256').update(Buffer.from(str, 'utf8')).digest('hex');
}

async function loadJson(path) {
  return JSON.parse(await readFile(new URL(path, import.meta.url), 'utf8'));
}

function importRawPublicKey(rawBytes) {
  // Wrap raw 32-byte Ed25519 public key in SPKI for Node's createPublicKey.
  const spkiPrefix = Buffer.from('302a300506032b6570032100', 'hex');
  const spki = Buffer.concat([spkiPrefix, rawBytes]);
  return createPublicKey({ key: spki, format: 'der', type: 'spki' });
}

async function verifySample(receipt, publicKey) {
  const hashContent = canonicalize(withoutSigAndHash(receipt));
  const expectedHash = 'sha256:' + sha256Hex(hashContent);
  const hashOk = receipt.hash_chain.receipt_hash === expectedHash;

  const sigContent = canonicalize(withoutSig(receipt));
  const sigBytes = b64urlDecode(receipt.signature.sig);
  const sigOk = verify(null, Buffer.from(sigContent, 'utf8'), publicKey, sigBytes);

  return { hashOk, sigOk };
}

const pk = await loadJson('./samples/public-key.json');
const rawBytes = b64urlDecode(pk.public_key_b64url);
const publicKey = importRawPublicKey(rawBytes);

const expectations = [
  { file: '01-valid.json',          expectHash: true,  expectSig: true  },
  { file: '02-tampered-body.json',  expectHash: false, expectSig: false },
  { file: '03-wrong-key.json',      expectHash: true,  expectSig: false },
  { file: '04-broken-chain.json',   expectHash: true,  expectSig: true  },
  { file: '05-replayed.json',       expectHash: true,  expectSig: true  },
];

let failures = 0;
for (const exp of expectations) {
  const receipt = await loadJson('./samples/' + exp.file);
  const { hashOk, sigOk } = await verifySample(receipt, publicKey);

  const hashOkMatches = hashOk === exp.expectHash;
  const sigOkMatches = sigOk === exp.expectSig;

  const status = hashOkMatches && sigOkMatches ? 'PASS' : 'FAIL';
  if (status === 'FAIL') failures++;

  console.log(
    `${status}  ${exp.file.padEnd(28)} hashOk=${hashOk} (expected ${exp.expectHash})  sigOk=${sigOk} (expected ${exp.expectSig})`,
  );
}

const s01 = await loadJson('./samples/01-valid.json');
const s04 = await loadJson('./samples/04-broken-chain.json');
const chainBroken = s04.hash_chain.prev_receipt_hash !== s01.hash_chain.receipt_hash;
console.log(`${chainBroken ? 'PASS' : 'FAIL'}  04 chain link         chainBroken=${chainBroken} (expected true)`);
if (!chainBroken) failures++;

const s05 = await loadJson('./samples/05-replayed.json');
const replayMatches = s01.receipt_id === s05.receipt_id;
console.log(`${replayMatches ? 'PASS' : 'FAIL'}  05 replay             sameReceiptId=${replayMatches} (expected true)`);
if (!replayMatches) failures++;

if (failures > 0) {
  console.error(`\n${failures} check(s) failed.`);
  process.exit(1);
}
console.log('\nAll samples behave as expected.');
