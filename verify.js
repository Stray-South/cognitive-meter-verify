// cognitive-meter receipt verifier — browser module.
//
// Verifies:
//   1. Signature covers the canonical form with `.signature` stripped.
//   2. `hash_chain.receipt_hash` equals sha256 of the canonical form with
//      BOTH `.signature` and `.hash_chain.receipt_hash` stripped.
//   3. `hash_chain.prev_receipt_hash` matches the previous receipt's
//      `hash_chain.receipt_hash` (when verifying a sequence).
//   4. `receipt_id` is unique across the sequence (replay detection).
//
// Spec clarification: the written spec is ambiguous about whether
// `receipt_hash` is part of the signed content. This verifier treats the
// signed content as "everything except `.signature`" — which means the
// `receipt_hash` IS part of what's signed, and is itself computed as a hash
// of everything except `.signature` and `.hash_chain.receipt_hash`.
// The sample generator follows the same convention.

import { canonicalize } from './canonicalize.mjs';

// ---------- Helpers ----------

function b64urlDecode(s) {
  const pad = '='.repeat((4 - (s.length % 4)) % 4);
  const b64 = (s + pad).replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(digest))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function withoutSig(receipt) {
  const { signature, ...rest } = receipt;
  return rest;
}

function withoutSigAndHash(receipt) {
  const { signature, hash_chain, ...rest } = receipt;
  const prunedChain = { prev_receipt_hash: hash_chain.prev_receipt_hash };
  return { ...rest, hash_chain: prunedChain };
}

async function importPublicKey(publicKeyB64url) {
  const raw = b64urlDecode(publicKeyB64url);
  return crypto.subtle.importKey(
    'raw',
    raw,
    { name: 'Ed25519' },
    true,
    ['verify'],
  );
}

// ---------- Single-receipt checks ----------

export async function verifyReceipt(receipt, publicKeyDoc) {
  const results = [];

  // 1. Structural sanity.
  if (receipt.receipt_version !== '0.1') {
    results.push({ check: 'version', ok: false, message: `Unsupported receipt_version: ${receipt.receipt_version}` });
    return { ok: false, results };
  }
  results.push({ check: 'version', ok: true, message: 'receipt_version = 0.1' });

  // 2. Key-id match.
  if (receipt.signature?.key_id !== publicKeyDoc.key_id) {
    results.push({
      check: 'key_id',
      ok: false,
      message: `Receipt declares key_id=${receipt.signature?.key_id}, but verifier loaded key_id=${publicKeyDoc.key_id}`,
    });
    return { ok: false, results };
  }
  results.push({ check: 'key_id', ok: true, message: `key_id = ${publicKeyDoc.key_id}` });

  // 3. Recompute receipt_hash.
  const canonicalForHash = new TextEncoder().encode(canonicalize(withoutSigAndHash(receipt)));
  const expectedHashHex = await sha256Hex(canonicalForHash);
  const declaredHash = receipt.hash_chain?.receipt_hash ?? '';
  const declaredHashHex = declaredHash.startsWith('sha256:') ? declaredHash.slice(7) : '';

  if (declaredHashHex !== expectedHashHex) {
    results.push({
      check: 'receipt_hash',
      ok: false,
      message: `receipt_hash mismatch. Declared: sha256:${declaredHashHex.slice(0, 16)}… Expected: sha256:${expectedHashHex.slice(0, 16)}…`,
    });
    // Still proceed to signature check so the user sees the full story.
  } else {
    results.push({ check: 'receipt_hash', ok: true, message: `receipt_hash matches (sha256:${expectedHashHex.slice(0, 16)}…)` });
  }

  // 4. Verify Ed25519 signature.
  let sigOk = false;
  try {
    const publicKey = await importPublicKey(publicKeyDoc.public_key_b64url);
    const canonicalForSig = new TextEncoder().encode(canonicalize(withoutSig(receipt)));
    const sigBytes = b64urlDecode(receipt.signature.sig);
    sigOk = await crypto.subtle.verify({ name: 'Ed25519' }, publicKey, sigBytes, canonicalForSig);
  } catch (err) {
    results.push({ check: 'signature', ok: false, message: `Signature verification threw: ${err.message}` });
    return { ok: false, results };
  }

  if (sigOk) {
    results.push({ check: 'signature', ok: true, message: 'Ed25519 signature valid' });
  } else {
    results.push({
      check: 'signature',
      ok: false,
      message: 'Ed25519 signature INVALID — content does not match what was signed, or key mismatch',
    });
  }

  const allOk = results.every(r => r.ok);
  return { ok: allOk, results };
}

// ---------- Chain-level checks ----------

export function verifyChainLink(current, previous) {
  if (!previous) {
    const sentinel = 'sha256:' + '0'.repeat(64);
    if (current.hash_chain.prev_receipt_hash !== sentinel) {
      return {
        check: 'chain_link',
        ok: false,
        message: `First receipt should have prev_receipt_hash = sentinel (zeros). Got: ${current.hash_chain.prev_receipt_hash.slice(0, 24)}…`,
      };
    }
    return { check: 'chain_link', ok: true, message: 'First receipt: prev_receipt_hash is sentinel' };
  }

  if (current.hash_chain.prev_receipt_hash !== previous.hash_chain.receipt_hash) {
    return {
      check: 'chain_link',
      ok: false,
      message: `prev_receipt_hash does not match previous receipt_hash. Chain is broken.`,
    };
  }

  return { check: 'chain_link', ok: true, message: 'prev_receipt_hash links correctly to previous receipt' };
}

export function detectReplay(receipt, seenIds) {
  if (seenIds.has(receipt.receipt_id)) {
    return {
      check: 'replay',
      ok: false,
      message: `Replay detected: receipt_id ${receipt.receipt_id} was already seen`,
    };
  }
  return { check: 'replay', ok: true, message: `receipt_id ${receipt.receipt_id} is unique in this session` };
}
