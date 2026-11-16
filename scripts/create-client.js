#!/usr/bin/env node
// Usage: node scripts/create-client.js <email> <client-name> [redirect-uri]
// Registers a confidential OAuth client for the given user and prints credentials once.

import { validRedirectUri } from "../src/http/redirect-uri.js";
import Database from "better-sqlite3";
import bcrypt from "bcrypt";
import { randomBytes, randomUUID } from "crypto";
import path from "path";

const [email, clientName, redirectUri] = process.argv.slice(2);

if (!email || !clientName || (redirectUri && !validRedirectUri(redirectUri)) || (email === "--set-redirect" && !redirectUri)) {
  console.error("Usage: node scripts/create-client.js <email> <client-name> [redirect-uri]");
  console.error("       node scripts/create-client.js --set-redirect <client-id> <redirect-uri>");
  process.exit(1);
}

const DATA_DIR = process.env.DATA_DIR || "/data";
const DB_PATH = path.join(DATA_DIR, "anylist-mcp.db");

(async () => {
  const db = new Database(DB_PATH);

  if (email === "--set-redirect") {
    const result = db.prepare("UPDATE oauth_clients SET redirect_uri = ? WHERE client_id = ? AND client_secret_hash IS NOT NULL").run(redirectUri, clientName);
    if (!result.changes) throw new Error("Confidential client not found.");
    console.log("Registered redirect URI updated.");
    return;
  }

  const user = db.prepare("SELECT id FROM users WHERE email = ?").get(email.toLowerCase());
  if (!user) {
    console.error(`No user found with email: ${email}`);
    process.exit(1);
  }

  const clientId = randomUUID();
  const clientSecret = randomBytes(32).toString("hex");
  const secretHash = await bcrypt.hash(clientSecret, 12);

  db.prepare(`
    INSERT INTO oauth_clients (client_id, client_secret_hash, user_id, client_name, redirect_uri)
    VALUES (?, ?, ?, ?, ?)
  `).run(clientId, secretHash, user.id, clientName, redirectUri || null);

  console.log("\nClient created successfully.\n");
  console.log(`  client_id:     ${clientId}`);
  console.log(`  client_secret: ${clientSecret}`);
  console.log("\nSave the client_secret now — it is not stored and cannot be retrieved later.\n");
})();
