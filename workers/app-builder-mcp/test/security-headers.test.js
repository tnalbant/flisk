import { test } from "node:test";
import assert from "node:assert/strict";
import worker from "../src/index.js";
import { withSecurityHeaders } from "../src/security-headers.js";

globalThis.caches ??= { default: { async match() {}, async put() {}, async delete() {} } };

const EXPECTED = {
  "x-content-type-options": "nosniff",
  "x-frame-options": "SAMEORIGIN",
  "strict-transport-security": "max-age=31536000; includeSubDomains",
  "referrer-policy": "strict-origin-when-cross-origin",
  "permissions-policy": "camera=(), microphone=(), geolocation=()",
  "content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-inline' https:; style-src 'self' 'unsafe-inline' https:; img-src 'self' data: blob: https:; font-src 'self' data: https:; connect-src 'self' https: wss:; media-src 'self' https:; frame-src 'self' https:; worker-src 'self' blob:; object-src 'none'; frame-ancestors 'self'; base-uri 'self'; form-action 'self' https:",
};

const check = (res) => {
  for (const [k, v] of Object.entries(EXPECTED)) assert.equal(res.headers.get(k), v, k);
};

test("pages, health, 404 and MCP responses all carry the baseline headers", async () => {
  const env = {};
  const ctx = { waitUntil() {} };
  check(await worker.fetch(new Request("https://build.flisk.si/"), env, ctx));
  check(await worker.fetch(new Request("https://build.flisk.si/health"), env, ctx));
  check(await worker.fetch(new Request("https://build.flisk.si/nope"), env, ctx));
  const mcp = await worker.fetch(
    new Request("https://build.flisk.si/mcp", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }) }),
    env,
    ctx,
  );
  check(mcp);
  assert.equal(mcp.headers.get("access-control-allow-origin"), "*");
  assert.equal((await mcp.json()).result.tools.length, 2);
});

test("existing headers are kept, not duplicated, and a CSP gains frame-ancestors", () => {
  const res = withSecurityHeaders(new Response("x", { headers: { "x-frame-options": "DENY", "content-security-policy": "default-src 'none'" } }));
  assert.equal(res.headers.get("x-frame-options"), "DENY");
  assert.equal(res.headers.get("content-security-policy"), "default-src 'none'; frame-ancestors 'self'");
  const keep = withSecurityHeaders(new Response("x", { headers: { "content-security-policy": "frame-ancestors https://a.example" } }));
  assert.equal(keep.headers.get("content-security-policy"), "frame-ancestors https://a.example");
});

test("the body stream passes through untouched", async () => {
  const stream = new ReadableStream({ start(c) { c.enqueue(new TextEncoder().encode("a")); c.enqueue(new TextEncoder().encode("b")); c.close(); } });
  const src = new Response(stream, { headers: { "content-type": "text/event-stream" } });
  const out = withSecurityHeaders(src);
  assert.equal(out.body, src.body);
  assert.equal(await out.text(), "ab");
});

test("the MCP Server Card is served at both well-known paths, identical, with baseline headers", async () => {
  const ctx = { waitUntil() {} };
  const a = await worker.fetch(new Request("https://mcp.flisk.sh/.well-known/mcp-server-card.json"), {}, ctx);
  const b = await worker.fetch(new Request("https://mcp.flisk.sh/.well-known/mcp/server-card.json"), {}, ctx);
  check(a);
  assert.equal(a.status, 200);
  assert.match(a.headers.get("content-type"), /^application\/json/);
  assert.equal(a.headers.get("access-control-allow-origin"), "*");
  const text = await a.text();
  assert.equal(text, await b.text());
  const card = JSON.parse(text);
  assert.equal(card.$schema, "https://static.modelcontextprotocol.io/schemas/v1/server-card.schema.json");
  assert.match(card.name, /^[^/]+\/[^/]+$/);
  assert.equal(card.remotes[0].url, "https://mcp.flisk.sh/mcp");
  const head = await worker.fetch(new Request("https://mcp.flisk.sh/.well-known/mcp-server-card.json", { method: "HEAD" }), {}, ctx);
  assert.equal(head.status, 200);
  const post = await worker.fetch(new Request("https://mcp.flisk.sh/.well-known/mcp-server-card.json", { method: "POST" }), {}, ctx);
  assert.equal(post.status, 404);
});

test("the home page carries the Flisk analytics beacon for build.flisk.si", async () => {
  const res = await worker.fetch(new Request("https://build.flisk.si/"), {}, { waitUntil() {} });
  assert.match(await res.text(), /<script defer data-domain="build\.flisk\.si" src="https:\/\/flisk\.sh\/a\.js"><\/script>/);
});
