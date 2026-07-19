// kms.etzhayyim.com thin edge facade (ADR-2604282300).
//
// Access-policy issuance for etzhayyim private records runs in the KMS
// LangServer pod. This Worker only exposes health/meta and proxies
// com.etzhayyim.kms.* XRPC calls to the dispatcher.
//
// Interim trust anchor: issuer = did:web:etzhayyim.com
// Migration target:     issuer = did:web:etzhayyim.com

interface SecretBinding {
  get(): Promise<string>;
}

interface Env {
  DISPATCHER_URL?: string;
  DISPATCHER_INTERNAL_SECRET?: string | SecretBinding;
  APP_HANDLE?: string;
  PRIMARY_DID?: string;
}

const NSID_PREFIX = "com.etzhayyim.kms.";

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);

    if (url.pathname === "/_app/meta" || url.pathname === "/health") {
      return json({
        ok: true,
        handle: env.APP_HANDLE ?? "kms.etzhayyim.com",
        did: env.PRIMARY_DID ?? "did:web:kms.etzhayyim.com",
        execution: "edge-proxy+agentgateway-mcp+langserver",
        businessLogic: "40-engine/kotoba/crates/kotoba-kotodama/py/src/kotodama/kms/handlers.py",
        issuer: "did:web:etzhayyim.com",
        migrationTarget: "did:web:etzhayyim.com",
        adr: "ADR-2604282300",
      });
    }

    const nsid = url.pathname.startsWith("/xrpc/") ? url.pathname.slice("/xrpc/".length) : "";
    if (nsid.startsWith(NSID_PREFIX) && (req.method === "POST" || req.method === "GET")) {
      let body: Record<string, unknown> = {};
      if (req.method === "POST") {
        try {
          const text = await req.text();
          body = text ? JSON.parse(text) : {};
        } catch (e) {
          return json({ ok: false, error: `invalid JSON body: ${e instanceof Error ? e.message : String(e)}` }, 400);
        }
      }
      for (const [key, value] of url.searchParams) {
        if (!(key in body)) body[key] = value;
      }
      const viewerDid = req.headers.get("x-etzhayyim-viewer-did");
      if (viewerDid && !body.callerDid) body.callerDid = viewerDid;
      return proxyToDispatcher(env, nsid, body);
    }

    return json({ error: "NotFound", message: "not found" }, 404);
  },
} satisfies ExportedHandler<Env>;

async function proxyToDispatcher(env: Env, nsid: string, body: Record<string, unknown>): Promise<Response> {
  const base = (env.DISPATCHER_URL ?? "https://dispatcher.etzhayyim.com").replace(/\/+$/, "");
  const headers: Record<string, string> = { "content-type": "application/json" };
  const trust = await internalTrustSecret(env);
  if (trust) headers["x-internal-trust"] = trust;
  const resp = await fetch(`${base}/xrpc/${nsid}`, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
  const text = await resp.text();
  return new Response(text, {
    status: resp.status,
    headers: {
      "content-type": resp.headers.get("content-type") ?? "application/json",
      "cache-control": "no-store",
    },
  });
}

async function internalTrustSecret(env: Env): Promise<string> {
  const binding = env.DISPATCHER_INTERNAL_SECRET;
  if (!binding) return "";
  try {
    return typeof binding === "string" ? binding : await binding.get();
  } catch {
    return "";
  }
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });
}
