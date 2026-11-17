import { validRedirectUri } from "../redirect-uri.js";
import { Router } from "express";
import { rateLimit } from "express-rate-limit";
import { createHash, randomBytes, randomUUID } from "crypto";
import bcrypt from "bcrypt";
import {
  getOAuthClient,
  registerOAuthClient,
  saveOAuthCode,
  getOAuthCode,
  exchangeOAuthCode,
  saveOAuthTokens,
  getTokenRecord,
  getTokenByRefresh,
  rotateOAuthTokens,
  getAnyListCredentials,
} from "../db.js";
import { loginWithPassword, registerWithPassword } from "./providers/password.js";
import { loginWithGoogle, isGoogleEnabled } from "./providers/google.js";

function renderLogin(res, error = "") {
  res.render("login", {
    error,
    googleEnabled: isGoogleEnabled(),
    googleClientId: process.env.GOOGLE_CLIENT_ID || "",
  });
}

const router = Router();

function requestLimit(identifier, limit, windowMs, options = {}) {
  return rateLimit({
    identifier, limit, windowMs, standardHeaders: "draft-8", legacyHeaders: false,
    message: { error: "rate_limited", error_description: "Try again after the Retry-After interval." },
    ...options,
  });
}

const minute = 60_000;
const signInLimit = requestLimit("sign-in", 10, 15 * minute);
const oauthLimit = requestLimit("oauth", 60, minute);
const registrationLimit = requestLimit("registration", 5, 60 * minute);
const totalRegistrations = requestLimit("total-registrations", 30, 60 * minute, {
  keyGenerator: () => "all",
});

// BASE_URL is optional: if not set, derive from the incoming request so the
// server works behind any proxy (including a Cloudflare quick tunnel) without
// needing to know its public URL at startup.
function baseUrl(req) {
  if (process.env.BASE_URL) return process.env.BASE_URL;
  if (req) return `${req.protocol}://${req.get("host")}${req.baseUrl || ""}`;
  return "http://localhost:3000";
}

// ── OAuth AS Metadata (RFC 8414) ──────────────────────────────────────────────

router.get("/.well-known/oauth-authorization-server", (req, res) => {
  const base = baseUrl(req);
  res.json({
    issuer: base,
    authorization_endpoint: `${base}/oauth/authorize`,
    token_endpoint: `${base}/oauth/token`,
    registration_endpoint: `${base}/oauth/register`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token", "client_credentials"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none", "client_secret_post"],
  });
});

// MCP protected resource metadata (RFC 9728)
// Handle both /.well-known/oauth-protected-resource and /.well-known/oauth-protected-resource/<path>
// so that HA (which appends the resource path per RFC 9728) gets the right resource URL.
router.get(["/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/*path"], (req, res) => {
  const base = baseUrl(req);
  const suffix = req.params.path ? `/${req.params.path}` : "";
  res.json({
    resource: `${base}${suffix}`,
    authorization_servers: [base],
    bearer_methods_supported: ["header"],
    scopes_supported: ["mcp"],
  });
});

// ── Dynamic Client Registration (RFC 7591) ────────────────────────────────────
// Home ASsistent expects /register, but Claude expects /oauth/register, so we support both.
router.post(["/oauth/register", "/register"], registrationLimit, totalRegistrations, (req, res) => {
  const { redirect_uris, client_name } = req.body || {};
  const clientId = randomUUID();
  const redirectUri = Array.isArray(redirect_uris) ? redirect_uris[0] : redirect_uris || null;
  if (!validRedirectUri(redirectUri)) {
    return res.status(400).json({ error: "invalid_redirect_uri" });
  }
  registerOAuthClient({ clientId, redirectUri });
  res.status(201).json({
    client_id: clientId,
    client_secret: "",
    redirect_uris: redirectUri ? [redirectUri] : [],
    client_name: client_name || "MCP Client",
    token_endpoint_auth_method: "none",
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
  });
});

// ── Authorization Endpoint ────────────────────────────────────────────────────
// Home ASsistent expects /authorize, but Claude expects /oauth/authorize, so we support both.

router.get(["/oauth/authorize", "/authorize"], oauthLimit, (req, res) => {
  const { client_id, redirect_uri, state, code_challenge, code_challenge_method, scope } = req.query;

  const client = typeof client_id === "string" && getOAuthClient(client_id);
  if (!client || !validRedirectUri(redirect_uri) || redirect_uri !== client.redirect_uri) {
    return res.status(400).send("Unknown client or unregistered redirect URI.");
  }
  if (req.query.response_type !== "code" || (state !== undefined && typeof state !== "string") ||
      (scope !== undefined && (typeof scope !== "string" || scope !== "mcp"))) {
    return res.status(400).send("Invalid authorization request.");
  }
  if (!client.client_secret_hash || code_challenge !== undefined || code_challenge_method !== undefined) {
    if (code_challenge_method !== "S256" || typeof code_challenge !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(code_challenge)) {
      return res.status(400).send("An S256 PKCE challenge is required.");
    }
  }

  req.session.oauthParams = { client_id, redirect_uri, state, code_challenge, code_challenge_method, scope,
    consentToken: randomBytes(32).toString("hex") };

  // If the user already has an active session, skip the login step
  if (req.session.userId) {
    const hasCreds = !!getAnyListCredentials(req.session.userId);
    return res.redirect(hasCreds ? "/oauth/consent" : "/setup");
  }

  res.redirect("/login");
});

// ── Token Endpoint ────────────────────────────────────────────────────────────

router.post(["/oauth/token", "/token"], oauthLimit, async (req, res) => {
  const body = req.body || {};
  const { grant_type } = body;
  res.set("Cache-Control", "no-store");

  if (grant_type === "authorization_code") {
    return handleAuthCodeGrant(req, res);
  }
  if (grant_type === "refresh_token") {
    return handleRefreshGrant(req, res);
  }
  if (grant_type === "client_credentials") {
    return handleClientCredentialsGrant(req, res);
  }
  return res.status(400).json({ error: "unsupported_grant_type" });
});

async function handleAuthCodeGrant(req, res) {
  const { code, redirect_uri, code_verifier, client_id, client_secret } = req.body;

  const client = typeof client_id === "string" && getOAuthClient(client_id);
  if (!client || !await authenticatesClient(client, client_secret)) {
    return res.status(401).json({ error: "invalid_client" });
  }
  const row = typeof code === "string" && getOAuthCode(code);
  if (!row || row.client_id !== client_id || !validRedirectUri(redirect_uri) ||
      redirect_uri !== row.redirect_uri || redirect_uri !== client.redirect_uri) {
    return res.status(400).json({ error: "invalid_grant" });
  }
  if (row.code_challenge || !client.client_secret_hash || code_verifier !== undefined) {
    if (row.challenge_method !== "S256" || typeof code_verifier !== "string" ||
        !/^[A-Za-z0-9._~-]{43,128}$/.test(code_verifier) ||
        createHash("sha256").update(code_verifier).digest("base64url") !== row.code_challenge) {
      return res.status(400).json({ error: "invalid_grant" });
    }
  }
  return issueTokens(res, row, tokens => exchangeOAuthCode(code, tokens));
}

async function authenticatesClient(client, secret) {
  if (!client.client_secret_hash) return !secret;
  return typeof secret === "string" && !!secret && bcrypt.compare(secret, client.client_secret_hash);
}

async function handleRefreshGrant(req, res) {
  const { refresh_token, client_id, client_secret } = req.body;
  const row = typeof refresh_token === "string" && getTokenByRefresh(refresh_token);
  if (!row || row.refresh_expires_at <= Math.floor(Date.now() / 1000) ||
      (client_id !== undefined && client_id !== row.client_id)) {
    return res.status(400).json({ error: "invalid_grant" });
  }
  const client = getOAuthClient(row.client_id);
  if (!client || (client.client_secret_hash && !client_id) || !await authenticatesClient(client, client_secret)) {
    return res.status(401).json({ error: "invalid_client" });
  }
  return issueTokens(res, row, tokens => rotateOAuthTokens(refresh_token, tokens));
}

function issueTokens(res, row, persist) {
  const accessToken = randomBytes(32).toString("hex");
  const refreshToken = randomBytes(32).toString("hex");
  if (!persist({ accessToken, refreshToken, userId: row.user_id, clientId: row.client_id, scope: row.scope })) {
    return res.status(400).json({ error: "invalid_grant" });
  }
  return res.json({
    access_token: accessToken, token_type: "Bearer", expires_in: 3600,
    refresh_token: refreshToken, scope: row.scope || "mcp",
  });
}

async function handleClientCredentialsGrant(req, res) {
  const { client_id, client_secret } = req.body;

  if (typeof client_id !== "string" || typeof client_secret !== "string" || !client_secret) {
    return res.status(400).json({ error: "invalid_request", error_description: "Missing client_id or client_secret" });
  }

  const client = getOAuthClient(client_id);
  if (!client || !client.client_secret_hash) {
    return res.status(401).json({ error: "invalid_client" });
  }

  const valid = await bcrypt.compare(client_secret, client.client_secret_hash);
  if (!valid) {
    return res.status(401).json({ error: "invalid_client" });
  }

  const accessToken = randomBytes(32).toString("hex");
  const refreshToken = randomBytes(32).toString("hex");
  saveOAuthTokens({
    accessToken,
    refreshToken,
    userId: client.user_id,
    clientId: client_id,
    scope: "mcp",
  });

  res.json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: 3600,
    scope: "mcp",
  });
}

// ── Login / Registration form handlers ───────────────────────────────────────

router.post("/auth/login", signInLimit, async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return renderLogin(res, "Email and password are required.");
  }
  try {
    const user = await loginWithPassword(email, password);
    return completeAuth(req, res, user);
  } catch (err) {
    return renderLogin(res, err.message);
  }
});

router.post("/auth/register", signInLimit, async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return renderLogin(res, "Email and password are required.");
  }
  try {
    const user = await registerWithPassword(email, password);
    return completeAuth(req, res, user);
  } catch (err) {
    return renderLogin(res, err.message);
  }
});

router.post("/auth/google", signInLimit, async (req, res) => {
  const { credential } = req.body || {};
  try {
    const user = await loginWithGoogle(credential);
    return completeAuth(req, res, user);
  } catch (err) {
    return renderLogin(res, err.message);
  }
});

function completeAuth(req, res, user) {
  const oauth = req.session.oauthParams;
  req.session.regenerate(err => {
    if (err) return res.sendStatus(500);
    req.session.userId = user.id;
    if (oauth) req.session.oauthParams = oauth;
    res.redirect(oauth && getAnyListCredentials(user.id) ? "/oauth/consent" : "/setup");
  });
}

/**
 * OAuth consent page — shown after AnyList setup if an OAuth flow is pending.
 */
router.get("/oauth/consent", (req, res) => {
  if (!req.session.userId || !req.session.oauthParams) {
    return res.redirect("/login");
  }
  // Render consent view
  res.render("consent", {
    clientId: req.session.oauthParams.client_id,
    redirectUri: req.session.oauthParams.redirect_uri,
    consentToken: req.session.oauthParams.consentToken,
    scope: req.session.oauthParams.scope || "mcp",
  });
});

router.post("/oauth/consent", (req, res) => {
  const { approve } = req.body || {};
  const oauth = req.session.oauthParams;
  const userId = req.session.userId;

  if (!userId || !oauth) return res.redirect("/login");

  if (!oauth.consentToken || req.body?.consentToken !== oauth.consentToken) return res.sendStatus(403);
  if (approve !== "yes") {
    delete req.session.oauthParams;
    const redirectUri = oauth.redirect_uri;
    const state = oauth.state;
    const url = new URL(redirectUri);
    url.searchParams.set("error", "access_denied");
    if (state) url.searchParams.set("state", state);
    return res.redirect(url.toString());
  }

  return issueCodeAndRedirect(req, res, userId, oauth);
});

function issueCodeAndRedirect(req, res, userId, oauth) {
  const code = randomBytes(16).toString("hex");
  saveOAuthCode({
    code,
    clientId: oauth.client_id,
    userId,
    redirectUri: oauth.redirect_uri,
    codeChallenge: oauth.code_challenge,
    challengeMethod: oauth.code_challenge_method || "S256",
    scope: oauth.scope,
  });
  delete req.session.oauthParams;

  const url = new URL(oauth.redirect_uri);
  url.searchParams.set("code", code);
  if (oauth.state) url.searchParams.set("state", oauth.state);
  res.redirect(url.toString());
}

// ── Bearer token validation middleware ────────────────────────────────────────

/**
 * Express middleware that validates Bearer tokens on the /mcp endpoint.
 * Sets req.userId on success; sends 401 on failure.
 */
export function requireBearerToken(req, res, next) {
  const auth = req.headers["authorization"] || "";
  if (!auth.startsWith("Bearer ")) {
    res.setHeader("WWW-Authenticate", `Bearer realm="${baseUrl(req)}", resource_metadata="${baseUrl(req)}/.well-known/oauth-protected-resource"`);
    return res.status(401).json({ error: "unauthorized" });
  }
  const token = auth.slice(7);
  const record = getTokenRecord(token);
  if (!record) {
    res.setHeader("WWW-Authenticate", `Bearer realm="${baseUrl(req)}", error="invalid_token"`);
    return res.status(401).json({ error: "invalid_token" });
  }
  if (record.expires_at < Math.floor(Date.now() / 1000)) {
    res.setHeader("WWW-Authenticate", `Bearer realm="${baseUrl(req)}", error="invalid_token"`);
    return res.status(401).json({ error: "invalid_token" });
  }
  req.userId = record.user_id;
  next();
}

export default router;
