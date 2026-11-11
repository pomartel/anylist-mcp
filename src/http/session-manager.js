import AnyListClient from "../anylist-client.js";
import { getAnyListCredentials } from "./db.js";

const IDLE_TIMEOUT_MS =
  (parseInt(process.env.ANYLIST_SESSION_IDLE_MINUTES, 10) || 30) * 60 * 1000;

function createClient(userId) {
  const creds = getAnyListCredentials(userId);
  if (!creds) {
    throw new Error("No AnyList credentials configured for this user. Complete setup first.");
  }
  return new AnyListClient({
    username: creds.username,
    password: creds.password,
    defaultListName: creds.defaultListName,
  });
}

export function createSessionManager(newClient = createClient, idleMs = IDLE_TIMEOUT_MS) {
  const sessions = new Map();
  const leases = new WeakMap();

  async function close(session) {
    leases.delete(session.client);
    try {
      await session.client.disconnect();
    } catch {
      console.error("Failed to disconnect an AnyList session");
    }
  }

  function evictSession(userId) {
    const session = sessions.get(userId);
    if (!session) return;
    sessions.delete(userId);
    clearTimeout(session.timer);
    if (!session.active) return close(session);
  }

  function getOrCreateSession(userId) {
    let session = sessions.get(userId);
    if (!session) {
      session = { userId, client: newClient(userId), active: 0, timer: null };
      sessions.set(userId, session);
      leases.set(session.client, session);
    }
    clearTimeout(session.timer);
    session.active++;
    return session.client;
  }

  function releaseSession(client) {
    const session = leases.get(client);
    if (!session) return;
    session.active--;
    if (session.active > 0) return;
    // Credentials may have changed while this command was running.
    if (sessions.get(session.userId) !== session) return close(session);
    session.timer = setTimeout(() => {
      if (sessions.get(session.userId) === session && !session.active) {
        void evictSession(session.userId);
      }
    }, idleMs);
    session.timer.unref();
  }

  return { getOrCreateSession, releaseSession, evictSession };
}

export const { getOrCreateSession, releaseSession, evictSession } = createSessionManager();
