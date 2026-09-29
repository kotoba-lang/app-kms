# app-kms — kagitaba KMS (kagitaba.kotoba.cloud)

Cloudflare Worker that issues/versions/revokes signed access policies for kagitaba
keychain items. See `README.md` for the full surface.

## Invariants

- `KMS_SIGNING_KEY_PEM` (ECDSA P-256 PKCS#8) exists only as a Worker secret. Never
  copy it into a repo, log, or vars block. The public JWK is published at
  `/.well-known/did.json` automatically.
- Policy CIDs are content-derived (`kms-sha256-<hex>` over canonical
  `{resourcePattern, recipients, issuer}`); the version chain is append-only —
  supersession is recorded, old records are never rewritten.
- Reads are public; every mutation requires the `ADMIN_TOKEN` bearer.
- kagitaba (the cljc library) must stay zero-dep: no crypto/store/network code goes
  into `orgs/kotoba-lang/kagitaba`. The hosted surface lives HERE.

## Layout

```
worker/
  src/app.ts        # the entire app: routing, KV store, ES256 JWT signing, DID doc
  test/app.test.ts  # vitest: auth, lifecycle, version chain, dedup, validation
  wrangler.jsonc    # name kagitaba-kms, KV binding POLICY_STORE, custom domain route
  package.json      # typecheck / test / deploy
```

## Ops

- Deploy: see README. The west pin is advanced via superproject `scripts/advance-pins.cljs`.
- CI: `.github/workflows/ci.yml` runs typecheck + vitest on push/PR.
- Rotation: generate a new P-256 key, `wrangler secret put KMS_SIGNING_KEY_PEM`, bump
  the `#kagitaba-kms-<n>` kid; old JWTs remain verifiable via archived DID doc versions.

## History

Extracted from `etzhayyim/root` `60-apps/etzhayyim-project-kms` (see migration.edn)
as an edge-proxy over a K8s dispatcher. 2026-09-18: rewritten self-contained for
`kagitaba.kotoba.cloud` — the upstream dispatcher and its RisingWave store no longer
exist (ADR-2605262130 deprecated that stack), so the Worker now owns issuance.
