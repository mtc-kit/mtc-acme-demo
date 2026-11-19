import test from 'node:test';
import assert from 'node:assert/strict';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { AcmeClient, endpoint } from '../src/acme.js';
import { accountFromSeed, decode64, utf8 } from '../src/crypto.js';

const origin = 'https://acme.example';
const directory = { newNonce: `${origin}/nonce`, newAccount: `${origin}/account`, newOrder: `${origin}/order` };
const json = (data, status = 200, headers = {}) => new Response(JSON.stringify(data), { status, headers });
const unpack = (text) => JSON.parse(new TextDecoder().decode(decode64(text)));

test('ACME JWS flow uses nonces, public JWK then kid, empty POST-as-GET and raw certificate bytes', async () => {
  const account = accountFromSeed(new Uint8Array(32));
  const seen = [];
  let nonce = 0;
  let badNonce = true;
  const client = new AcmeClient(account, async (url, options) => {
    assert.equal(options.credentials, 'omit');
    assert.equal(options.redirect, 'error');
    if (url === `${origin}/directory`) return json(directory);
    if (options.method === 'HEAD') return new Response(null, { headers: { 'Replay-Nonce': `nonce-${++nonce}` } });
    const body = JSON.parse(options.body);
    const header = unpack(body.protected);
    assert.equal(header.alg, 'ML-DSA-65');
    assert.equal(header.url, url);
    assert.equal(header.nonce, `nonce-${nonce}`);
    assert(ml_dsa65.verify(decode64(body.signature), utf8(`${body.protected}.${body.payload}`), decode64(account.jwk.pub)));
    seen.push({ header, payload: body.payload ? unpack(body.payload) : null, url });
    const headers = { 'Replay-Nonce': `nonce-${++nonce}` };
    if (url === directory.newAccount) {
      assert.deepEqual(header.jwk, account.jwk);
      assert.equal(header.kid, undefined);
      if (badNonce) {
        badNonce = false;
        return json({ type: 'urn:ietf:params:acme:error:badNonce' }, 400, headers);
      }
      return json({ status: 'valid' }, 201, { ...headers, Location: `${origin}/acct/1` });
    }
    assert.equal(header.kid, `${origin}/acct/1`);
    assert.equal(header.jwk, undefined);
    if (url === directory.newOrder) return json({
      status: 'pending', authorizations: [`${origin}/auth/1`], finalize: `${origin}/finalize/1`,
    }, 201, { ...headers, Location: `${origin}/orders/1` });
    if (url === `${origin}/certificate`) {
      assert.equal(body.payload, '');
      assert.equal(options.headers.Accept, 'application/pem-certificate-chain-with-properties');
      return new Response(new Uint8Array([0, 255, 128, 1]), { headers });
    }
    assert.equal(body.payload, '');
    return json({ status: 'valid', certificate: `${origin}/certificate` }, 200, headers);
  });
  await client.connect(`${origin}/directory`);
  await client.register('test@example.com', true);
  const order = await client.newOrder(['example.com']);
  assert.equal(order.url, `${origin}/orders/1`);
  assert.deepEqual(seen[0].payload, { termsOfServiceAgreed: true, contact: ['mailto:test@example.com'] });
  assert.deepEqual(seen[2].payload, { identifiers: [{ type: 'dns', value: 'example.com' }] });
  assert.equal((await client.poll(order.url, (value) => value.status === 'valid')).status, 'valid');
  const { response } = await client.post(`${origin}/certificate`, null, false, {
    raw: true, headers: { Accept: 'application/pem-certificate-chain-with-properties' },
  });
  assert.deepEqual(new Uint8Array(await response.arrayBuffer()), new Uint8Array([0, 255, 128, 1]));
});

test('reject unsafe endpoint schemes, credentials, and fragments', () => {
  for (const value of ['javascript:alert(1)', 'http://acme.example/', '******acme.example/', 'https://acme.example/#x']) {
    assert.throws(() => endpoint(value));
  }
  assert.equal(endpoint('http://localhost:3000/directory'), 'http://localhost:3000/directory');
  assert.equal(endpoint('https://acme.example/directory'), 'https://acme.example/directory');
});

test('missing exposed nonce fails with actionable error', async () => {
  const client = new AcmeClient(accountFromSeed(new Uint8Array(32)), async () => new Response(null));
  client.directory = directory;
  await assert.rejects(client.register('', true), /Replay-Nonce.*CORS/);
});

test('badNonce retries are bounded and terminal authorization failures stop polling', async () => {
  let requests = 0;
  const client = new AcmeClient(accountFromSeed(new Uint8Array(32)), async () => {
    requests++;
    return json({ type: 'urn:ietf:params:acme:error:badNonce', detail: 'Rejected' }, 400, { 'Replay-Nonce': 'next' });
  });
  client.directory = directory;
  client.nonce = 'first';
  await assert.rejects(client.register('', true), /Rejected/);
  assert.equal(requests, 3);
  client.kid = `${origin}/acct/1`;
  client.fetch = async () => json({ status: 'invalid', error: { detail: 'DNS failed' } });
  await assert.rejects(client.poll(`${origin}/auth`, () => false), /DNS failed/);
});
