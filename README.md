# cognitive-meter-verify

A zero-dependency browser demo that verifies `cognitive-meter` v0.1 receipts.

**Live demo:** https://stray-south.github.io/cognitive-meter-verify
**Spec:** [cognitive-meter-public](https://github.com/Stray-South/cognitive-meter-public)

## What it does

Paste a receipt — or click one of five bundled samples — and the page runs the full verification chain against it:

1. **Signature** — Ed25519 signature over the canonicalized receipt (minus `.signature`).
2. **Receipt hash** — `hash_chain.receipt_hash` equals SHA-256 of the canonical form with `.signature` and `.hash_chain.receipt_hash` stripped.
3. **Chain link** — `prev_receipt_hash` matches the previous receipt's `receipt_hash`.
4. **Replay** — `receipt_id` has not been seen before in this session.

Each check reports pass/fail independently, so you can see exactly what broke and why.

## Why this exists

The `cognitive-meter` spec is language-neutral and text-only. A spec without a reference verifier is a polite suggestion. This demo:

- Makes the spec executable in the simplest possible environment (a single HTML file).
- Provides test vectors (the five sample receipts) that any implementation can be cross-checked against.
- Demonstrates what tampering looks like from the verifier's perspective.

## The five samples

| # | File | What it exercises |
|---|------|-------------------|
| 01 | `01-valid.json` | Well-formed receipt, valid signature, sentinel prev-hash. Everything passes. |
| 02 | `02-tampered-body.json` | Identical to #01 but `meter.tokens.output` was edited after signing. Signature fails. |
| 03 | `03-wrong-key.json` | Signed with a second keypair but declares the legitimate `key_id`. Signature fails. |
| 04 | `04-broken-chain.json` | Valid signature, but `prev_receipt_hash` does not match #01's `receipt_hash`. Chain fails. |
| 05 | `05-replayed.json` | Identical `receipt_id` to #01, re-signed with a fresh timestamp. Replay detection fails. |

## Running locally

No build step, no package manager. You just need a static-file server (the `file://` protocol blocks `fetch`).

```bash
# Any HTTP server works. One-liners:
python3 -m http.server 8080
# or
npx --yes serve -p 8080
```

Then open http://localhost:8080.

## Regenerating samples

The bundled samples are generated with `generate-samples.mjs`, which uses Node's built-in `crypto` module. Run:

```bash
node generate-samples.mjs
```

A fresh keypair is generated on each run, so sample files and `public-key.json` update together. Commit them as a set.

## Browser support

Uses `Ed25519` in Web Crypto API:

- Chrome 113+ (May 2023)
- Firefox 129+ (August 2024)
- Safari 17+ (September 2023)
- Edge 113+

The page does a feature-detection probe on load and disables the Verify button if Ed25519 isn't available.

## Spec clarification embedded in this demo

The written spec says the signature covers "everything except the `signature` field itself," and `receipt_hash` covers "the canonicalized content, same as the signature input." That wording is circular — if `receipt_hash` is part of the signed content, it cannot also be a hash of that content.

This verifier resolves the ambiguity by treating them as follows:

- **`receipt_hash`** = SHA-256 of canonicalize(receipt minus `.signature` minus `.hash_chain.receipt_hash`)
- **`signature`** = Ed25519 over canonicalize(receipt minus `.signature`) — which means the signature commits to `receipt_hash`

Both the generator and the verifier follow this convention. If the spec changes, both sides update together.

## What this would need to go from demo to production

This is an intentional MVP. Straightforward next moves:

- Replace the hand-rolled JCS canonicalizer with a vetted library (the `canonicalize` npm package, or a WASM build).
- Pull the public key from `signature.verify_keys_url` (the demo uses a local-relative URL).
- Support multi-issuer key rotation by fetching a key set rather than a single key.
- Accept receipts via drag-and-drop of an NDJSON file to verify sequences end-to-end.
- Add a URL-encoded "share this receipt" permalink for bug reports.

## License

Apache 2.0. See [LICENSE](./LICENSE).
