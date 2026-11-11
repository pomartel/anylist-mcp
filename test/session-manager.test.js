import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { test } from "node:test";
import { createSessionManager } from "../src/http/session-manager.js";
import { registerAllTools } from "../src/tools/index.js";
import { createMockServer, MockAnyListClient } from "./tools/helpers.js";

test("idle shopping sessions stop receiving changes and the next call connects a fresh client", async t => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const changes = new EventEmitter();
  let opened = 0, closed = 0, refreshed = 0;
  const sessions = createSessionManager(() => {
    const client = new MockAnyListClient();
    const refresh = () => refreshed++;
    const connect = client.connect.bind(client);
    client.connect = async name => {
      if (!client.targetList) { opened++; changes.on("change", refresh); }
      await connect(name);
    };
    client.disconnect = async () => { closed++; changes.off("change", refresh); };
    return client;
  }, 100);
  const { server, handlers } = createMockServer();
  registerAllTools(server, () => sessions.getOrCreateSession("user"), sessions.releaseSession);
  const read = async () => assert.ok(!(await handlers.shopping({ action: "list_lists" })).isError);
  await read();
  t.mock.timers.tick(90);
  await read();
  t.mock.timers.tick(99);
  changes.emit("change");
  assert.deepEqual([opened, closed, refreshed], [1, 0, 1]);
  t.mock.timers.tick(1);
  changes.emit("change");
  assert.deepEqual([opened, closed, refreshed], [1, 1, 1]);
  await read();
  changes.emit("change");
  assert.deepEqual([opened, closed, refreshed], [2, 1, 2]);
  await sessions.evictSession("user");
});

test("a busy or evicted session finishes its commands and cannot close its replacement", async t => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const closed = [];
  const sessions = createSessionManager(() => {
    const client = { disconnect: async () => closed.push(client) };
    return client;
  }, 100);
  const old = sessions.getOrCreateSession("user");
  assert.equal(sessions.getOrCreateSession("user"), old);
  sessions.releaseSession(old);
  t.mock.timers.tick(200);
  assert.deepEqual(closed, []);
  await sessions.evictSession("user");
  const fresh = sessions.getOrCreateSession("user");
  assert.notEqual(old, fresh);
  await sessions.releaseSession(old);
  assert.deepEqual(closed, [old]);
  t.mock.timers.tick(200);
  assert.deepEqual(closed, [old]);
  sessions.releaseSession(fresh);
  t.mock.timers.tick(100);
  assert.deepEqual(closed, [old, fresh]);
});

test("a failed tool call also releases its session", async t => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  let closed = 0;
  const sessions = createSessionManager(() => ({
    connect: async () => { throw new Error("offline"); },
    disconnect: async () => { closed++; },
  }), 10);
  const { server, handlers } = createMockServer();
  registerAllTools(server, () => sessions.getOrCreateSession("user"), sessions.releaseSession);
  assert.equal((await handlers.health_check({})).isError, true);
  t.mock.timers.tick(10);
  assert.equal(closed, 1);
});
