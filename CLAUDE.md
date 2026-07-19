# etzhayyim-project-kms

KMS (Key Management Service) for etzhayyim private records (kms.etzhayyim.com).
Issues, manages, and revokes signed access policies that authorize specific DIDs
to decrypt `com.etzhayyim.private.*` records.

## Layer Metadata

```
layer:           L3 Dispatcher → L7 LangServer pod
nsid_prefix:     com.etzhayyim.kms
did:             did:web:kms.etzhayyim.com
issuer (interim):did:web:etzhayyim.com
migration target:did:web:etzhayyim.com
```

## Architecture

- **Runtime**: TS Native edge proxy (`worker/src/app.ts` → `wrangler.jsonc`)
- **Business logic**: `40-engine/kotoba/crates/kotoba-kotodama/py/src/kotodama/kms/handlers.py` (L7 pod)
- **Signing key**: ES256 EC P-256, injected as K8s secret `KMS_SIGNING_KEY_PEM`
- **Dev mode**: unsigned HS256 JWT (when `KMS_SIGNING_KEY_PEM` is absent)
- **Storage**: RisingWave `vertex_kms_access_policy`
- **Migration**: `40-engine/kotoba/crates/kotoba-kotodama/py/src/kotodama/kms/migrations/0001_init.sql`

## XRPC Methods (5)

| NSID | Type | Description |
|------|------|-------------|
| `com.etzhayyim.kms.issueAccessPolicy`  | procedure | Issue signed policy → `policyCid` + `policyJwt` |
| `com.etzhayyim.kms.getAccessPolicy`    | query     | Retrieve policy by CID |
| `com.etzhayyim.kms.addRecipient`       | procedure | Add DID → new CID (policy version chain) |
| `com.etzhayyim.kms.removeRecipient`    | procedure | Remove DID → new CID |
| `com.etzhayyim.kms.revokeAccessPolicy` | procedure | Mark policy revoked |

## Policy CID format

`kms-sha256-{sha256hex}` — SHA-256 of canonical JSON `{resourcePattern, recipients, issuer}`.
Upgrade path: replace with IPFS CIDv1 (base32 SHA2-256) when etzhayyim IPFS pinning is active.

## Migration to etzhayyim trust anchor

1. Generate new EC P-256 signing key for `did:web:etzhayyim.com`
2. Update `KMS_ISSUER_DID` env var to `did:web:etzhayyim.com`
3. Re-issue active policies under new issuer
4. Client verifier accepts both issuers during transition window
5. After cutover: deprecate `did:web:etzhayyim.com` KMS signing key

## Vault invariant

`KMS_SIGNING_KEY_PEM` never leaves the K8s pod. Policy JWTs are signed
server-side; client never sees the private key. Consistent with
CLAUDE.md §Vault Zero-Knowledge Invariant.

## Environment variables

| Var | Required | Description |
|-----|----------|-------------|
| `KMS_SIGNING_KEY_PEM` | prod only | EC P-256 private key PEM |
| `KMS_ISSUER_DID`      | optional  | Default: `did:web:etzhayyim.com` |
| `INTERNAL_TRUST_TOKEN`| optional  | Shared secret for x-internal-trust header |
