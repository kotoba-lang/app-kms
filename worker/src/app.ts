// kagitaba.kotoba.cloud — KMS app (access-policy issuance for kagitaba vault records).
//
// Self-contained Cloudflare Worker: ES256 (P-256) policy JWTs signed with a
// secret-held key (never leaves the Worker), policies stored in a KV namespace,
// issuer = did:web:kagitaba.kotoba.cloud with a public /.well-known/did.json.
//
// Design lineage: kotoba-lang/kagitaba (1Password-compatible keychain data
// model, ADR-2607023000) + kagi/kagitaba security closure (ADR-2607198200).
// kagitaba itself stays a zero-dep library; THIS worker is the hosted KMS
// consumer that issues the signed access policies around kagitaba items.

const NSID_PREFIX = "cloud.kotoba.kms.";
const ISSUER_DID = "did:web:kagitaba.kotoba.cloud";
const HANDLE = "kagitaba.kotoba.cloud";

interface Env {
  POLICY_STORE: KVNamespace;
  KMS_SIGNING_KEY_PEM?: string;
  ADMIN_TOKEN?: string;
}

type Rec = {
  cid: string;
  policy: { resourcePattern: string; recipients: string[]; issuer: string };
  jwt: string;
  revoked?: boolean;
  supersededBy?: string;
  supersedes?: string;
  createdAt: string;
  updatedAt: string;
};

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);

    if (url.pathname === "/.well-known/did.json") return didDoc(env);
    if (url.pathname === "/_app/meta" || url.pathname === "/health") {
      return json({
        ok: true,
        app: "kagitaba-kms",
        handle: HANDLE,
        did: ISSUER_DID,
        execution: "cloudflare-worker+kv",
        signing: "ES256 (ECDSA P-256, WebCrypto)",
        nsidPrefix: NSID_PREFIX,
        storage: "POLICY_STORE (Workers KV)",
        adr: ["ADR-2607023000", "ADR-2607198200"],
        signingKeyLoaded: await keyImportable(env),
      });
    }
    if (url.pathname === "/" && req.method === "GET") {
      return new Response(LANDING, { headers: { "content-type": "text/html; charset=utf-8" } });
    }

    if (!url.pathname.startsWith("/xrpc/")) return json({ error: "NotFound" }, 404);
    const nsid = url.pathname.slice("/xrpc/".length);
    if (!nsid.startsWith(NSID_PREFIX)) return json({ error: "NotFound", message: `unknown nsid ${nsid}` }, 404);
    const method = nsid.slice(NSID_PREFIX.length);

    let body: Record<string, unknown> = {};
    if (req.method === "POST") {
      try {
        const text = await req.text();
        body = text ? JSON.parse(text) : {};
      } catch (e) {
        return json({ ok: false, error: `invalid JSON body: ${e instanceof Error ? e.message : String(e)}` }, 400);
      }
    }
    for (const [k, v] of url.searchParams) if (!(k in body)) body[k] = v;

    if (method === "getAccessPolicy") return getPolicy(env, String(body.policyCid ?? ""));

    // mutations require the admin bearer token
    const denied = requireAdmin(req, env);
    if (denied) return denied;

    switch (method) {
      case "issueAccessPolicy": return issue(env, body);
      case "addRecipient": return mutateRecipients(env, body, "add");
      case "removeRecipient": return mutateRecipients(env, body, "remove");
      case "revokeAccessPolicy": return revoke(env, body);
      default: return json({ error: "NotFound", message: `unknown method ${method}` }, 404);
    }
  },
} satisfies ExportedHandler<Env>;

function requireAdmin(req: Request, env: Env): Response | null {
  if (!env.ADMIN_TOKEN) return json({ ok: false, error: "misconfigured: ADMIN_TOKEN secret not set" }, 503);
  const h = req.headers.get("authorization") ?? "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : req.headers.get("x-kagitaba-admin") ?? "";
  if (!timingSafeEqual(token, env.ADMIN_TOKEN)) return json({ ok: false, error: "unauthorized" }, 401);
  return null;
}

async function issue(env: Env, body: Record<string, unknown>): Promise<Response> {
  const resourcePattern = String(body.resourcePattern ?? "");
  const recipients = Array.isArray(body.recipients) ? body.recipients.map(String) : [];
  if (!resourcePattern.startsWith("kagitaba://") || resourcePattern.length < 14)
    return json({ ok: false, error: "resourcePattern required, e.g. kagitaba://vault/<id>/**" }, 400);
  if (recipients.some((r) => !/^did:[a-z0-9]+:/.test(r)))
    return json({ ok: false, error: "all recipients must be DID strings" }, 400);
  if (!env.KMS_SIGNING_KEY_PEM) return json({ ok: false, error: "signing key not configured" }, 503);

  const policy = { resourcePattern, recipients: norm(recipients), issuer: ISSUER_DID };
  const cid = await policyCid(policy);
  const existing = await env.POLICY_STORE.get<Rec>(cid, "json");
  if (existing) return json({ ok: true, policyCid: cid, policyJwt: existing.jwt, deduped: true });
  const jwt = await signEs256(policy, env);
  const now = new Date().toISOString();
  const rec: Rec = { cid, policy, jwt, createdAt: now, updatedAt: now };
  await env.POLICY_STORE.put(cid, JSON.stringify(rec));
  return json({ ok: true, policyCid: cid, policyJwt: jwt }, 201);
}

async function mutateRecipients(env: Env, body: Record<string, unknown>, op: "add" | "remove"): Promise<Response> {
  const cid = String(body.policyCid ?? "");
  const did = String(body.did ?? "");
  if (!cid || !/^did:[a-z0-9]+:/.test(did)) return json({ ok: false, error: "policyCid and a valid did required" }, 400);
  const head = await loadHead(env, cid);
  if (!head) return json({ ok: false, error: "policy not found or revoked" }, 404);
  if (!env.KMS_SIGNING_KEY_PEM) return json({ ok: false, error: "signing key not configured" }, 503);

  const set = new Set(head.policy.recipients);
  if (op === "add") set.add(did);
  else if (!set.delete(did)) return json({ ok: false, error: "did not in recipients" }, 400);
  const policy = { ...head.policy, recipients: norm([...set]) };
  const newCid = await policyCid(policy);
  if (newCid === head.cid) {
    // no-op mutation (did already present): same content -> same CID -> same JWT
    return json({ ok: true, policy: head.policy, policyCid: head.cid, policyJwt: head.jwt, supersedes: head.supersedes ?? null, deduped: true });
  }
  const now = new Date().toISOString();
  const jwt = await signEs256(policy, env);
  const rec: Rec = { cid: newCid, policy, jwt, supersedes: head.cid, createdAt: now, updatedAt: now };
  await env.POLICY_STORE.put(newCid, JSON.stringify(rec));
  head.supersededBy = newCid;
  head.updatedAt = now;
  await env.POLICY_STORE.put(head.cid, JSON.stringify(head));
  return json({ ok: true, policy: rec.policy, policyCid: newCid, policyJwt: jwt, supersedes: head.cid }, 201);
}

async function revoke(env: Env, body: Record<string, unknown>): Promise<Response> {
  const cid = String(body.policyCid ?? "");
  const rec = cid ? await env.POLICY_STORE.get<Rec>(cid, "json") : null;
  if (!rec) return json({ ok: false, error: "policy not found" }, 404);
  rec.revoked = true;
  rec.updatedAt = new Date().toISOString();
  await env.POLICY_STORE.put(cid, JSON.stringify(rec));
  return json({ ok: true, policyCid: cid, revoked: true });
}

async function getPolicy(env: Env, cid: string): Promise<Response> {
  if (!cid) return json({ ok: false, error: "policyCid required" }, 400);
  const rec = await env.POLICY_STORE.get<Rec>(cid, "json");
  if (!rec) return json({ ok: false, error: "policy not found" }, 404);
  const head = rec.supersededBy ? await findHead(env, rec) : rec;
  return json({
    ok: true,
    policyCid: head.cid,
    policyJwt: head.jwt,
    policy: head.policy,
    revoked: !!head.revoked,
    supersededBy: head.supersededBy ?? null,
    supersedes: head.supersedes ?? null,
    createdAt: head.createdAt,
    updatedAt: head.updatedAt,
  });
}

async function findHead(env: Env, rec: Rec): Promise<Rec> {
  let cur = rec;
  for (let i = 0; i < 64 && cur.supersededBy; i++) {
    const next = await env.POLICY_STORE.get<Rec>(cur.supersededBy, "json");
    if (!next) break;
    cur = next;
  }
  return cur;
}

async function loadHead(env: Env, cid: string): Promise<Rec | null> {
  const rec = await env.POLICY_STORE.get<Rec>(cid, "json");
  if (!rec || rec.revoked) return null;
  const head = rec.supersededBy ? await findHead(env, rec) : rec;
  return head.revoked ? null : head;
}

function norm(dids: string[]): string[] {
  return [...new Set(dids)].sort();
}

async function policyCid(p: { resourcePattern: string; recipients: string[]; issuer: string }): Promise<string> {
  const canon = JSON.stringify({ resourcePattern: p.resourcePattern, recipients: norm(p.recipients), issuer: p.issuer });
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canon));
  const hex = [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
  return `kms-sha256-${hex}`;
}

// ---- ES256 signing (WebCrypto, P-256) ----

let keyCache: { pem: string; key: CryptoKey } | null = null;

async function signingKey(env: Env): Promise<CryptoKey> {
  const pem = env.KMS_SIGNING_KEY_PEM!;
  if (keyCache?.pem === pem) return keyCache.key;
  const der = pemToDer(pem);
  const key = await crypto.subtle.importKey("pkcs8", der, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  keyCache = { pem, key };
  return key;
}

async function signEs256(payload: object, env: Env): Promise<string> {
  const key = await signingKey(env);
  const enc = new TextEncoder();
  const b64 = (u: Uint8Array) => btoa(String.fromCharCode(...u)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const header = b64(enc.encode(JSON.stringify({ alg: "ES256", typ: "JWT", kid: `${ISSUER_DID}#kagitaba-kms-1` })));
  const claims = b64(enc.encode(JSON.stringify({ iss: ISSUER_DID, sub: payload, iat: Math.floor(Date.now() / 1000) })));
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, enc.encode(`${header}.${claims}`)));
  return `${header}.${claims}.${b64(sig)}`;
}

async function didDoc(env: Env): Promise<Response> {
  const verificationMethod: unknown[] = [];
  if (env.KMS_SIGNING_KEY_PEM) {
    try {
      // importing a private key requires non-empty usages; export JWK (public part only)
      const key = await crypto.subtle.importKey("pkcs8", pemToDer(env.KMS_SIGNING_KEY_PEM), { name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]);
      const jwk = (await crypto.subtle.exportKey("jwk", key)) as unknown as Record<string, unknown>;
      delete jwk.d; // exportKey on a private key includes the private scalar — strip for a public JWK
      delete jwk.key_ops; // private-key ops must not leak into the public verification method
      delete jwk.ext;
      verificationMethod.push({
        id: `${ISSUER_DID}#kagitaba-kms-1`,
        type: "JsonWebKey2020",
        controller: ISSUER_DID,
        publicKeyJwk: jwk,
      });
    } catch {
      /* misconfigured key: serve DID doc without verification method */
    }
  }
  return json({
    "@context": "https://www.w3.org/ns/did/v1",
    id: ISSUER_DID,
    verificationMethod,
    service: [{ id: "#kms-xrpc", type: "KmsXrpcService", serviceEndpoint: `https://${HANDLE}/xrpc/` }],
  });
}

function pemToDer(pem: string): Uint8Array {
  const b64 = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  const bin = atob(b64);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

/** True iff the signing secret is present AND parseable as a P-256 PKCS#8 key. */
async function keyImportable(env: Env): Promise<boolean> {
  if (!env.KMS_SIGNING_KEY_PEM) return false;
  try {
    await crypto.subtle.importKey("pkcs8", pemToDer(env.KMS_SIGNING_KEY_PEM), { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
    return true;
  } catch {
    return false;
  }
}

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });
}

const LANDING = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>kagitaba KMS - kotoba.cloud</title>
<style>body{font-family:ui-sans-serif,system-ui,sans-serif;margin:0;background:#0b0d10;color:#e8eaed;line-height:1.6}main{max-width:52rem;margin:0 auto;padding:3rem 1.5rem}h1{font-size:1.6rem}code,pre{font-family:ui-monospace,monospace;background:#151a21;padding:.15rem .4rem;border-radius:4px}pre{padding:1rem;overflow-x:auto}a{color:#7ab4ff}</style></head>
<body><main><h1>kagitaba KMS</h1>
<p>Access-policy issuance for <a href="https://github.com/kotoba-lang/kagitaba">kagitaba</a> keychain items (1Password-compatible vault data model, ADR-2607023000). Policies are signed ES256 JWTs; issuer <code>${ISSUER_DID}</code>.</p>
<p>XRPC methods (prefix <code>${NSID_PREFIX}</code>): <code>issueAccessPolicy</code> / <code>getAccessPolicy</code> / <code>addRecipient</code> / <code>removeRecipient</code> / <code>revokeAccessPolicy</code>. Mutations require an admin bearer token.</p>
<pre>curl -s https://${HANDLE}/health
curl -s "https://${HANDLE}/xrpc/${NSID_PREFIX}getAccessPolicy?policyCid=..."
curl -s -X POST -H "Authorization: Bearer $ADMIN" -H 'content-type: application/json' \\
  -d '{"resourcePattern":"kagitaba://vault/demo/**","recipients":["did:example:alice"]}' \\
  https://${HANDLE}/xrpc/${NSID_PREFIX}issueAccessPolicy</pre>
<p><a href="/.well-known/did.json">DID document</a> / <a href="/health">health</a></p>
</main></body></html>`;
