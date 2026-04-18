# Security Policy

This repository contains a demo verifier for the `cognitive-meter` receipt format. The crypto primitives (Ed25519, SHA-256) come from the browser's Web Crypto API; the canonicalization and verification logic are in-repo and have not been independently audited.

**Do not use this as a production verifier.** Use it as a reference implementation and a test bench.

## Reporting a vulnerability

If you identify:

- A way to make this verifier accept a receipt that should not verify.
- A mismatch between this verifier's behavior and the spec in [cognitive-meter-public](https://github.com/Stray-South/cognitive-meter-public).
- An issue with the JCS canonicalization that could produce different results than the spec requires.
- A way the sample-generator produces receipts that should not be possible under the spec.

Please report privately:

- **Email** — `ljfreeman83@gmail.com` with `[SECURITY: cognitive-meter-verify]` in the subject.
- **Response time** — acknowledgment within two business days, triage within five.

Do not open public GitHub issues for security topics.

## Scope

In scope:

- `canonicalize.mjs` — canonicalization correctness.
- `verify.js` — signature, hash, chain, replay check logic.
- `generate-samples.mjs` — sample receipt construction.
- `index.html` — any XSS or script-injection path in the verifier UI.

Out of scope (welcome as normal issues):

- Browser compatibility glitches with older browsers.
- UI and copy feedback.
- Suggestions for additional sample receipts.

## Disclosure

Reporters are credited on release notes unless they request otherwise. Spec-level issues are forwarded to the `cognitive-meter-public` repository for versioning.
