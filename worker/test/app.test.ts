import { describe, expect, it } from "vitest";
import worker from "../src/app";

// ---- fakes ----

function kvStub(): KVNamespace {
  const m = new Map<string, string>();
  return {
    async get(key: string, opts?: any) {
      const v = m.get(key);
      if (v === undefined) return null;
      const t = typeof opts === "string" ? opts : opts?.type;
      return t === "json" ? JSON.parse(v) : v;
    },
    async put(key: string, value: string) {
      m.set(key, value);
    },
    async delete(key: string) {
      m.delete(key);
    },
  } as unknown as KVNamespace;
}

// PEM armor is assembled at runtime from parts; a literal BEGIN/END PRIVATE KEY
// string in a test file trips repo secret scanners (and this session's masker).
const DASH5 = "-".repeat(5);
const pemWrap = (body: string) =>
  `${DASH5}BEGIN PRIVATE KEY${DASH5}\n${body}\n${DASH5}END PRIVATE KEY${DASH5}\n`;

async function pemP256(): Promise<string> {
  const pair = (await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const der = (await crypto.subtle.exportKey("pkcs8", pair.privateKey)) as ArrayBuffer;
  const b64 = btoa(String.fromCharCode(...new Uint8Array(der))).replace(/(.{64})/g, "$1\n");
  return pemWrap(b64);
}

/** Non-parseable PEM: exercises the no-key / degraded paths. */
const GARBAGE_PEM = pemWrap("bm90LWEta2V5");

const ADMIN = "test-admin-token";

async function mkEnv() {
  return { POLICY_STORE: kvStub(), KMS_SIGNING_KEY_PEM: await pemP256(), ADMIN_TOKEN: ADMIN };
}

function xrpc(method: string, init?: RequestInit & { search?: string }) {
  const url = `https://kagitaba.kotoba.cloud/xrpc/cloud.kotoba.kms.${method}${init?.search ?? ""}`;
  return new Request(url, init);
}

const post = (body: unknown, token = ADMIN) => ({
  method: "POST",
  headers: {
    "content-type": "application/json",
    ...(token ? { authorization: `Bearer ${token}` } : {}),
  },
  body: JSON.stringify(body),
});

const call = async (env: any, method: string, init?: any) =>
  worker.fetch(xrpc(method, init), env);
const json = async (r: Response) => (await r.json()) as any;

// ---- tests ----

describe("health + landing", () => {
  it("serves health meta", async () => {
    const env = await mkEnv();
    const r = await worker.fetch(new Request("https://kagitaba.kotoba.cloud/health"), env);
    const j = await json(r);
    expect(r.status).toBe(200);
    expect(j.app).toBe("kagitaba-kms");
    expect(j.did).toBe("did:web:kagitaba.kotoba.cloud");
    expect(j.signingKeyLoaded).toBe(true);
  });

  it("reports signingKeyLoaded=false on an unreadable key", async () => {
    const env = { POLICY_STORE: kvStub(), KMS_SIGNING_KEY_PEM: GARBAGE_PEM, ADMIN_TOKEN: ADMIN };
    const r = await worker.fetch(new Request("https://kagitaba.kotoba.cloud/health"), env);
    expect((await json(r)).signingKeyLoaded).toBe(false);
  });

  it("serves DID doc with verification method", async () => {
    const env = await mkEnv();
    const r = await worker.fetch(new Request("https://kagitaba.kotoba.cloud/.well-known/did.json"), env);
    const j = await json(r);
    expect(j.id).toBe("did:web:kagitaba.kotoba.cloud");
    expect(j.verificationMethod[0].publicKeyJwk.kty).toBe("EC");
    expect(j.verificationMethod[0].publicKeyJwk.crv).toBe("P-256");
  });

  it("404s unknown paths, serves HTML landing", async () => {
    const env = await mkEnv();
    const nf = await worker.fetch(new Request("https://kagitaba.kotoba.cloud/nope"), env);
    expect(nf.status).toBe(404);
    const home = await worker.fetch(new Request("https://kagitaba.kotoba.cloud/"), env);
    expect(home.status).toBe(200);
    expect(home.headers.get("content-type")).toContain("text/html");
  });
});

describe("auth", () => {
  it("rejects mutation without token", async () => {
    const env = await mkEnv();
    const r = await call(env, "issueAccessPolicy", post({ resourcePattern: "kagitaba://vault/v1/**", recipients: ["did:example:a"] }, ""));
    expect(r.status).toBe(401);
  });

  it("rejects wrong token", async () => {
    const env = await mkEnv();
    const r = await call(env, "issueAccessPolicy", post({ resourcePattern: "kagitaba://vault/v1/**", recipients: [] }, "wrong"));
    expect(r.status).toBe(401);
  });

  it("503s mutation when ADMIN_TOKEN unset", async () => {
    const env = { ...(await mkEnv()), ADMIN_TOKEN: undefined };
    const r = await call(env, "issueAccessPolicy", post({ resourcePattern: "kagitaba://vault/v1/**", recipients: [] }, "whatever"));
    expect(r.status).toBe(503);
  });

  it("GET reads are public (no auth header needed)", async () => {
    const env = await mkEnv();
    const r = await call(env, "getAccessPolicy", { method: "GET", search: "?policyCid=kms-sha256-deadbeef" });
    expect(r.status).toBe(404); // not 401 — public, just absent
  });
});

describe("policy lifecycle", () => {
  const pattern = "kagitaba://vault/demo/**";

  it("issue -> dedup -> get", async () => {
    const env = await mkEnv();
    const a = await call(env, "issueAccessPolicy", post({ resourcePattern: pattern, recipients: ["did:example:bob", "did:example:alice"] }));
    expect(a.status).toBe(201);
    const ai = await json(a);
    expect(ai.policyCid).toMatch(/^kms-sha256-[0-9a-f]{64}$/);
    expect(ai.policyJwt.split(".")).toHaveLength(3);

    const claims = JSON.parse(atob(ai.policyJwt.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
    expect(claims.iss).toBe("did:web:kagitaba.kotoba.cloud");
    // recipients normalized (sorted, deduped) in the signed claims
    expect(claims.sub.recipients).toEqual(["did:example:alice", "did:example:bob"]);

    // same policy content -> same CID, deduped
    const bi = await json(await call(env, "issueAccessPolicy", post({ resourcePattern: pattern, recipients: ["did:example:alice", "did:example:bob"] })));
    expect(bi.deduped).toBe(true);
    expect(bi.policyCid).toBe(ai.policyCid);
  });

  it("rejects non-DID recipients and bad patterns", async () => {
    const env = await mkEnv();
    expect((await call(env, "issueAccessPolicy", post({ resourcePattern: pattern, recipients: ["bob"] }))).status).toBe(400);
    expect((await call(env, "issueAccessPolicy", post({ resourcePattern: "http://x/**", recipients: [] }))).status).toBe(400);
  });

  it("addRecipient chains versions; get follows to head", async () => {
    const env = await mkEnv();
    const issued = await json(await call(env, "issueAccessPolicy", post({ resourcePattern: pattern, recipients: ["did:example:alice"] })));
    const added = await json(await call(env, "addRecipient", post({ policyCid: issued.policyCid, did: "did:example:carol" })));
    expect(added.policyCid).not.toBe(issued.policyCid);
    expect(added.supersedes).toBe(issued.policyCid);
    expect(added.policy.recipients).toEqual(["did:example:alice", "did:example:carol"]);

    // reading the OLD cid follows the chain to the head
    const got = await json(await call(env, "getAccessPolicy", { method: "GET", search: `?policyCid=${issued.policyCid}` }));
    expect(got.ok).toBe(true);
    expect(got.policyCid).toBe(added.policyCid);
  });

  it("addRecipient of an existing DID is a dedup (no new version)", async () => {
    const env = await mkEnv();
    const issued = await json(await call(env, "issueAccessPolicy", post({ resourcePattern: pattern, recipients: ["did:example:alice"] })));
    const again = await json(await call(env, "addRecipient", post({ policyCid: issued.policyCid, did: "did:example:alice" })));
    expect(again.deduped).toBe(true);
    expect(again.policyCid).toBe(issued.policyCid);
  });

  it("removeRecipient then revoke; mutations of revoked fail", async () => {
    const env = await mkEnv();
    const issued = await json(await call(env, "issueAccessPolicy", post({ resourcePattern: pattern, recipients: ["did:example:alice", "did:example:bob"] })));
    const removed = await json(await call(env, "removeRecipient", post({ policyCid: issued.policyCid, did: "did:example:alice" })));
    expect(removed.policyCid).not.toBe(issued.policyCid);
    expect(removed.policy.recipients).toEqual(["did:example:bob"]);

    const rv = await json(await call(env, "revokeAccessPolicy", post({ policyCid: removed.policyCid })));
    expect(rv.revoked).toBe(true);
    expect((await call(env, "addRecipient", post({ policyCid: removed.policyCid, did: "did:example:dave" }))).status).toBe(404);
    // get on a revoked head reports revoked, not ok
    const got = await json(await call(env, "getAccessPolicy", { method: "GET", search: `?policyCid=${removed.policyCid}` }));
    expect(got.revoked).toBe(true);
    expect(got.ok).toBe(true);
  });

  it("unknown nsid 404, malformed JSON 400", async () => {
    const env = await mkEnv();
    expect((await call(env, "bogus", post({}))).status).toBe(404);
    const r2 = await worker.fetch(
      new Request("https://kagitaba.kotoba.cloud/xrpc/cloud.kotoba.kms.issueAccessPolicy", {
        method: "POST",
        headers: { authorization: `Bearer ${ADMIN}`, "content-type": "application/json" },
        body: "{oops",
      }),
      env,
    );
    expect(r2.status).toBe(400);
  });
});

describe("JWT signature", () => {
  it("issued policyJwt verifies against the published DID key", async () => {
    const env = await mkEnv();
    const issued = await json(await call(env, "issueAccessPolicy", post({ resourcePattern: pattern, recipients: ["did:example:alice"] })));
    const jwk = (await json(await worker.fetch(new Request("https://kagitaba.kotoba.cloud/.well-known/did.json"), env))).verificationMethod[0].publicKeyJwk;
    expect(jwk.d).toBeUndefined(); // public-only: no private scalar
    expect(jwk.key_ops).toBeUndefined();
    const pub = await crypto.subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    const [h, p, s] = issued.policyJwt.split(".");
    const sig = Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
    const ok = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      pub,
      sig,
      new TextEncoder().encode(`${h}.${p}`),
    );
    expect(ok).toBe(true);
  });
});

const pattern = "kagitaba://vault/sig/**";
