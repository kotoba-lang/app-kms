# kagitaba-kms (kagitaba.kotoba.cloud)

Hosted **KMS app** for [kagitaba](https://github.com/kotoba-lang/kagitaba) keychain
items — issues, versions, and revokes **signed access policies** (ES256 JWTs) that
authorize specific DIDs to read a `kagitaba://…` resource pattern.

- Runtime: single self-contained **Cloudflare Worker** + **Workers KV** (no external
  dispatcher, no pod, no Postgres).
- Issuer DID: `did:web:kagitaba.kotoba.cloud` — published at `/.well-known/did.json`
  with the `kagitaba-kms-1` JsonWebKey2020 verification method.
- Signing key: PKCS#8 ECDSA P-256 PEM held **only** as Worker secret
  `KMS_SIGNING_KEY_PEM`; the private key never leaves the runtime and is exported
  public-only for the DID doc.
- Policy CID: `kms-sha256-<hex>` = SHA-256 over canonical
  `{resourcePattern, recipients(sorted,deduped), issuer}` — deterministic, so
  re-issuing the same policy dedups.
- Version chain: `addRecipient` / `removeRecipient` create a new CID and mark the old
  head `supersededBy`; `getAccessPolicy` on any CID follows the chain to the head.
  `revokeAccessPolicy` tombstones a policy; revoked heads reject mutation (404).
- Auth: reads (`getAccessPolicy`, `/health`, DID doc) are public. Mutations require
  `Authorization: Bearer $ADMIN_TOKEN` (constant-time compared).

## XRPC methods (prefix `cloud.kotoba.kms.`)

| NSID | Type | Description |
|------|------|-------------|
| `cloud.kotoba.kms.issueAccessPolicy`  | procedure | Issue signed policy → `policyCid` + `policyJwt` |
| `cloud.kotoba.kms.getAccessPolicy`    | query     | Retrieve head policy by any CID in its chain |
| `cloud.kotoba.kms.addRecipient`       | procedure | Add DID → new CID (version chain) |
| `cloud.kotoba.kms.removeRecipient`    | procedure | Remove DID → new CID |
| `cloud.kotoba.kms.revokeAccessPolicy` | procedure | Mark policy revoked |

```bash
curl -s https://kagitaba.kotoba.cloud/health
curl -s "https://kagitaba.kotoba.cloud/xrpc/cloud.kotoba.kms.getAccessPolicy?policyCid=kms-sha256-…"
curl -s -X POST -H "Authorization: Bearer $KAGITABA_ADMIN_TOKEN" -H 'content-type: application/json' \
  -d '{"resourcePattern":"kagitaba://vault/demo/**","recipients":["did:example:alice"]}' \
  https://kagitaba.kotoba.cloud/xrpc/cloud.kotoba.kms.issueAccessPolicy
```

## Relation to kagitaba / kagi

kagitaba stays a zero-dep cljc data-model library (ADR-2607023000): no crypto, no
persistence, no network. This Worker is one of its hosted *consumers* — the enterprise
KMS surface closing ADR-2607198200's G-005/G-008 deployment-qualification gap
("policy issuance with deployment qualification"), separate from kagi's client-side
PQC custody path.

## Development

```bash
cd worker
npm install
npm run typecheck   # tsc --noEmit
npm test            # vitest run (in-process fetch handler tests)
```

## Deploy

```bash
cd worker
npx wrangler kv namespace create kagitaba-kms-policy   # paste id into wrangler.jsonc
npx wrangler secret put KMS_SIGNING_KEY_PEM            # PKCS#8 P-256 PEM
npx wrangler secret put ADMIN_TOKEN
npm run deploy                                         # binds kagitaba.kotoba.cloud
```

Account `network-awai` (4da88288dc30d9ee257f319d3c33ecf0), zone `kotoba.cloud`.
The custom-domain route creates its DNS record automatically on first deploy.
