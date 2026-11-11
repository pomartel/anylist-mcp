import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import AnyList from '../anylist-js/lib/index.js';
import AnyListClient, { governHttp } from '../src/anylist-client.js';

test('a real HTTP 429 blocks subsequent SDK data and auth dispatches', async t => {
  let calls = 0, paused = false;
  const server = createServer((_req, res) => {
    calls++;
    res.writeHead(429, { 'Retry-After': '600' }).end();
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const sdk = new AnyList({ email: 'test@example.invalid', password: 'test' });
  sdk.clientId = 'test-client';
  sdk.accessToken = 'test-token';
  const url = 'http://127.0.0.1:' + server.address().port;
  for (const key of ['client', 'authClient']) sdk[key] = sdk[key].extend({ prefixUrl: url });
  governHttp(sdk, {
    normalize({ response }) {
      assert.equal(response.headers['retry-after'], '600');
      paused = true;
      return new Error('account paused');
    },
    assertAvailable() { if (paused) throw new Error('account paused'); },
  });
  await assert.rejects(sdk.client.get('data/test'), /429/);
  await assert.rejects(sdk.authClient.post('auth/token'), /account paused/);
  await assert.rejects(sdk.client.get('data/test'));
  assert.equal(calls, 1);
});

test('governed sessions refresh on demand without opening a second recovery socket', async t => {
  let reads = 0, paused = false;
  t.mock.method(AnyList.prototype, 'login', async socket => { assert.equal(socket, false); });
  t.mock.method(AnyList.prototype, 'getLists', async function () {
    reads++;
    this.lists = [{ name: 'Epicerie' }];
  });
  const client = new AnyListClient({ username: 'fixture', password: 'fixture', defaultListName: 'Epicerie' });
  client.governor = { assertAvailable() { if (paused) throw new Error('paused'); }, close() {} };
  t.after(() => client.disconnect());
  await Promise.all([client.connect(), client.connect()]);
  assert.equal(reads, 1);
  paused = true;
  await assert.rejects(client.connect(), /paused/);
  assert.equal(reads, 1);
  paused = false;
  await client.connect();
  assert.equal(reads, 2);
});
