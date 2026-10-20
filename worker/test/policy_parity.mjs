// aiueos/kms_policy.cljk（判定コア）と正本 worker/src/app.ts の実行 parity。
// Worker の fetch を mock KV + webcrypto で直接実行し、guest の判定結果と
// 同じ分岐になることを照合する（node の型 strip で TS をそのまま import）。
import worker from "../src/app.ts";
import assert from "node:assert";
import { webcrypto } from "node:crypto";

// --- mock env -------------------------------------------------------------
const store = new Map();
const kv = {
  async get(k, type) { const v = store.get(k); return v == null ? null : (type === "json" ? JSON.parse(v) : v); },
  async put(k, v) { store.set(k, v); },
};
const kp = await webcrypto.subtle.generateKey(
  { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
const pkcs8 = Buffer.from(await webcrypto.subtle.exportKey("pkcs8", kp.privateKey)).toString("base64")
  .replace(/(.{64})/g, "$1\n");
const pem = `-----BEGIN PRIVATE KEY-----\n${pkcs8}\n-----END PRIVATE KEY-----`;
const env = { POLICY_STORE: kv, KMS_SIGNING_KEY_PEM: pem, ADMIN_TOKEN: "adm" };

const call = (method, body, auth) =>
  worker.fetch(new Request(`https://kms.test/xrpc/cloud.kotoba.kms.${method}`, {
    method: "POST",
    headers: { "content-type": "application/json", ...(auth ? { authorization: `Bearer ${auth}` } : {}) },
    body: JSON.stringify(body),
  }), env);

// guest test-auth-misconfig: secret 未設定は 503（mutation）
const envNoSecret = { POLICY_STORE: kv, ADMIN_TOKEN: "adm" };
let r = await worker.fetch(new Request("https://kms.test/xrpc/cloud.kotoba.kms.issueAccessPolicy", {
  method: "POST", headers: { "content-type": "application/json", authorization: "Bearer adm" },
  body: JSON.stringify({ resourcePattern: "kagitaba://x/1", recipients: ["did:key:z"] }),
}), envNoSecret);
assert.equal(r.status, 503);

// guest test-auth-unauth: 誤 token は 401
r = await call("issueAccessPolicy", { resourcePattern: "kagitaba://x/1", recipients: ["did:key:z"] }, "wrong");
assert.equal(r.status, 401);

// guest test-auth-read: read は public（get が認可無しで動く）
// guest test-issue: 形が揃えば発行（admin）
r = await call("issueAccessPolicy", { resourcePattern: "kagitaba://vault/entry-1", recipients: ["did:key:zAbc", "did:web:example.com"] }, "adm");
assert.ok(r.ok);
const issued = await r.json();
assert.ok(issued.policyCid.startsWith("kms-sha256-"));
const cid1 = issued.policyCid;

// guest test-dedup: 同一 canonical（recipients の順不同・重複あり）は dedup
r = await call("issueAccessPolicy", { resourcePattern: "kagitaba://vault/entry-1", recipients: ["did:web:example.com", "did:key:zAbc", "did:key:zAbc"] }, "adm");
const dedup = await r.json();
assert.equal(dedup.deduped, true);
assert.equal(dedup.policyCid, cid1);

// guest test-pattern / test-recipient: 形外は拒否
r = await call("issueAccessPolicy", { resourcePattern: "vault/entry-1", recipients: ["did:key:zAbc"] }, "adm");
assert.ok(!r.ok);
r = await call("issueAccessPolicy", { resourcePattern: "kagitaba://vault/entry-1", recipients: ["alice"] }, "adm");
assert.ok(!r.ok);

// guest test-chain: addRecipient は新 CID を作り、旧 head に supersededBy
r = await call("addRecipient", { policyCid: cid1, did: "did:key:zNew" }, "adm");
const v2 = await r.json(); assert.notEqual(v2.policyCid, cid1);
r = await call("getAccessPolicy", { policyCid: cid1 });
const followed = await r.json();
assert.equal(followed.policyCid, v2.policyCid);

// guest test-revoked: revoke 後の head は mutation を拒む（404）
r = await call("revokeAccessPolicy", { policyCid: v2.policyCid }, "adm");
assert.equal((await r.json()).ok, true);
r = await call("addRecipient", { policyCid: v2.policyCid, did: "did:key:zNo" }, "adm");
assert.equal(r.status, 404);

console.log("kms parity_vectors: all pass");
