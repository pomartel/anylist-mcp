import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes, createHash } from "node:crypto";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { createInterface } from "node:readline";
import bcrypt from "bcrypt";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

test("OAuth registration, consent, code exchange and refresh", { timeout: 15000 }, async t => {
  const dir = await mkdtemp(join(tmpdir(), "anylist-oauth-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const email = "tester@example.invalid";
  const password = randomBytes(24).toString("hex");
  const callback = "https://client.example/callback?lang=en&view=app";
  await writeFile(join(dir, "allow"), email);
  process.env.DATA_DIR = dir;
  process.env.SERVER_SECRET_KEY = randomBytes(32).toString("hex");
  const db = await import("../src/http/db.js");
  db.createUser({ id: "tester", email, pwHash: await bcrypt.hash(password, 4) });
  db.upsertAnyListCredentials("tester", { username: email, password });
  const confidential = "private-client";
  const secret = randomBytes(24).toString("hex");
  db.getDb().prepare("INSERT INTO oauth_clients (client_id, redirect_uri, client_secret_hash, user_id) VALUES (?, ?, ?, ?)").run(
    confidential, callback, await bcrypt.hash(secret, 4), "tester");
  t.after(() => db.getDb().close());

  const child = spawn(process.execPath, ["src/http/index.js"], { env: {
    ...process.env, HOST: "127.0.0.1", PORT: "0", ALLOWED_EMAILS_FILE: join(dir, "allow"),
    SESSION_SECRET: randomBytes(32).toString("hex"), ANYLIST_GOVERNOR_MODULE: "", ANYLIST_GOVERNOR_DATABASE: "",
  }, stdio: ["ignore", "pipe", "inherit"] });
  const ended = once(child, "exit");
  t.after(async () => { child.kill(); await ended; });
  let base;
  const lines = createInterface({ input: child.stdout });
  for await (const line of lines) {
    const match = line.match(/listening on port (\d+)/);
    if (match) { base = "http://127.0.0.1:" + match[1]; break; }
  }
  assert.ok(base);
  let cookie = "";
  async function request(path, form, headers = {}) {
    const options = { redirect: "manual", headers: { ...headers, cookie } };
    if (form) Object.assign(options, { method: "POST", body: new URLSearchParams(form) });
    const response = await fetch(base + path, options);
    cookie = response.headers.get("set-cookie")?.split(";")[0] ?? cookie;
    return response;
  }
  async function register() {
    const res = await request("/register", { redirect_uris: callback });
    assert.equal(res.status, 201);
    return (await res.json()).client_id;
  }
  const clientId = await register();
  const other = await register();
  const verifier = randomBytes(32).toString("base64url");
  const params = { client_id: clientId, redirect_uri: callback, response_type: "code", state: "roundtrip",
    code_challenge: createHash("sha256").update(verifier).digest("base64url"), code_challenge_method: "S256" };
  async function authorize(params) { return request("/authorize?" + new URLSearchParams(params)); }
  async function consent(approve) {
    const page = await (await request("/oauth/consent")).text();
    assert.ok(page.includes("lang=en&amp;view=app"));
    const nonce = page.match(/name="consentToken" value="([a-f0-9]+)"/)[1];
    assert.equal((await request("/oauth/consent", { approve })).status, 403);
    const res = await request("/oauth/consent", { approve, consentToken: nonce });
    const location = new URL(res.headers.get("location"));
    assert.equal(location.searchParams.get("state"), "roundtrip");
    return location.searchParams;
  }
  assert.equal((await authorize({ ...params, client_id: "unregistered" })).status, 400);
  assert.equal((await authorize({ ...params, redirect_uri: "https://client.example/other" })).status, 400);
  assert.equal((await authorize(params)).headers.get("location"), "/login");
  assert.equal((await request("/auth/login", { email, password })).headers.get("location"), "/oauth/consent");
  assert.equal((await consent("no")).get("error"), "access_denied");
  assert.equal((await authorize(params)).headers.get("location"), "/oauth/consent");
  const code = (await consent("yes")).get("code");
  const exchange = { grant_type: "authorization_code", code, client_id: clientId, redirect_uri: callback, code_verifier: verifier };
  for (const change of [{ client_id: other }, { redirect_uri: "https://client.example/other" }]) {
    assert.equal((await request("/token", { ...exchange, ...change })).status, 400);
  }
  const token = await request("/oauth/token", exchange);
  assert.equal(token.status, 200);
  const issued = await token.json();
  const mcp = new Client({ name: "test-client", version: "1" });
  const transport = new StreamableHTTPClientTransport(new URL(base + "/mcp"), {
    requestInit: { headers: { Authorization: "Bearer " + issued.access_token } },
  });
  await mcp.connect(transport);
  try {
    const catalog = await mcp.listTools();
    assert.ok(catalog.tools.some(tool => tool.name === "shopping" && tool.inputSchema.type === "object"));
    await transport.terminateSession();
  } finally {
    await mcp.close();
  }
  const refresh = { grant_type: "refresh_token", refresh_token: issued.refresh_token, client_id: clientId };
  assert.equal((await request("/token", exchange)).status, 400);
  assert.equal((await request("/token", { ...refresh, client_id: other })).status, 400);
  assert.equal((await request("/token", refresh)).status, 200);
  assert.equal((await request("/token", refresh)).status, 400);

  assert.equal((await authorize({ ...params, client_id: confidential })).headers.get("location"), "/oauth/consent");
  const privateGrant = { ...exchange, client_id: confidential, code: (await consent("yes")).get("code") };
  assert.equal((await request("/token", privateGrant)).status, 401);
  assert.equal((await request("/token", { ...privateGrant, client_secret: secret })).status, 200);

  await t.test("registration aliases and sign-in forms share their respective quotas", async () => {
    const source = { "X-Forwarded-For": "192.0.2.11" };
    const registration = { redirect_uris: callback };
    for (const path of ["/register", "/oauth/register", "/mcp/register", "/mcp/oauth/register", "/register"]) {
      assert.equal((await request(path, registration, source)).status, 201);
    }
    const limited = await request("/mcp/oauth/register", registration, source);
    assert.equal(limited.status, 429);
    assert.ok(Number(limited.headers.get("Retry-After")) > 0);
    assert.equal((await limited.json()).error, "rate_limited");
    assert.equal((await request("/register", registration, { "X-Forwarded-For": "192.0.2.12" })).status, 201);

    for (let i = 0; i < 10; i++) {
      assert.equal((await request("/auth/login", {}, source)).status, 200);
    }
    for (const path of ["/mcp/auth/login", "/auth/register", "/auth/google"]) {
      assert.equal((await request(path, {}, source)).status, 429);
    }
    assert.equal((await request("/token", {}, source)).status, 400);
    assert.equal((await request("/health", undefined, source)).headers.has("RateLimit"), false);
  });
});
