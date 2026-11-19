import test from 'node:test';
import assert from 'node:assert/strict';
import { createPublicKey, verify } from 'node:crypto';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { accountFromSeed, base64url, decode64, generateCsr, parseCsr, parseDomains, sha256, utf8, pem, loadAccount, clearAccount, ACCOUNT_COOKIE } from '../src/crypto.js';

test('ML-DSA accounts restore from a compact seed and sign valid JOSE messages', async () => {
  const seed = crypto.getRandomValues(new Uint8Array(32));
  const first = accountFromSeed(seed);
  const restored = accountFromSeed(decode64(base64url(seed)));
  assert.deepEqual(restored.jwk, first.jwk);
  assert.deepEqual(Object.keys(first.jwk).sort(), ['alg', 'kty', 'pub']);
  assert.equal(first.jwk.alg, 'ML-DSA-65');
  const message = utf8('protected.payload');
  assert(ml_dsa65.verify(first.sign(message), message, decode64(first.jwk.pub)));
  assert.equal(await first.thumbprint(), base64url(await sha256(utf8(JSON.stringify({
    alg: first.jwk.alg, kty: first.jwk.kty, pub: first.jwk.pub,
  })))));
  assert.throws(() => accountFromSeed(new Uint8Array(31)));
});

test('DNS names are normalized and invalid identifiers rejected', () => {
  assert.deepEqual(parseDomains('Example.COM, *.example.com\nexample.com'), ['example.com', '*.example.com']);
  for (const invalid of ['', 'https://example.com', '-bad.example', 'foo..example', 'foo.*.example', 'x'.repeat(64) + '.com']) {
    assert.throws(() => parseDomains(invalid));
  }
});

function readDer(bytes, offset = 0) {
  const start = offset;
  const tag = bytes[offset++];
  let length = bytes[offset++];
  if (length & 0x80) {
    const count = length & 0x7f;
    length = 0;
    for (let i = 0; i < count; i++) length = length * 256 + bytes[offset++];
  }
  return { tag, body: bytes.slice(offset, offset + length), full: bytes.slice(start, offset + length), end: offset + length };
}

test('generated PKCS#10 CSR has a verifiable signature, SANs, and matching private key', async () => {
  const generated = await generateCsr(['example.com', '*.example.com']);
  const csr = parseCsr(generated.csr);
  assert.deepEqual(csr, generated.der);
  const root = readDer(csr);
  const info = readDer(root.body);
  const algorithm = readDer(root.body, info.end);
  const signature = readDer(root.body, algorithm.end);
  const version = readDer(info.body);
  const subject = readDer(info.body, version.end);
  const spki = readDer(info.body, subject.end);
  const publicKey = createPublicKey({ key: Buffer.from(spki.full), format: 'der', type: 'spki' });
  assert(verify('sha256', info.full, publicKey, signature.body.slice(1)));
  assert.deepEqual(publicKey.export({ format: 'jwk' }), createPublicKey(generated.privateKey).export({ format: 'jwk' }));
  const attributes = readDer(info.body, spki.end);
  const request = readDer(attributes.body);
  const requestOid = readDer(request.body);
  assert.equal(Buffer.from(requestOid.body).toString('hex'), '2a864886f70d01090e');
  const values = readDer(request.body, requestOid.end);
  const extensions = readDer(values.body);
  const san = readDer(extensions.body);
  const sanOid = readDer(san.body);
  assert.equal(Buffer.from(sanOid.body).toString('hex'), '551d11');
  const critical = readDer(san.body, sanOid.end);
  assert.deepEqual(Array.from(critical.body), [255]);
  const octets = readDer(san.body, critical.end);
  const names = readDer(octets.body);
  const firstName = readDer(names.body);
  const secondName = readDer(names.body, firstName.end);
  assert.equal(firstName.tag, 0x82);
  assert.equal(new TextDecoder().decode(firstName.body), 'example.com');
  assert.equal(new TextDecoder().decode(secondName.body), '*.example.com');
});

test('pasted CSR must be a complete PEM DER sequence', async () => {
  assert.throws(() => parseCsr('not a CSR'));
  assert.throws(() => parseCsr(pem('CERTIFICATE REQUEST', new Uint8Array([0x30, 0x80, 0, 0]))));
  const generated = await generateCsr(['example.com']);
  const truncated = generated.der.slice(0, -1);
  assert.throws(() => parseCsr(pem('CERTIFICATE REQUEST', truncated)));
});

test('CSR DER length encoding supports large SAN lists without truncation', async () => {
  const domains = Array.from({ length: 1100 }, (_, i) => `${'a'.repeat(58)}${i}.example.com`);
  const generated = await generateCsr(domains);
  assert(generated.der.length > 65535);
  assert.deepEqual(parseCsr(generated.csr), generated.der);
  assert.equal(readDer(generated.der).end, generated.der.length);
});

test('account cookie persists only a seed, restores identity, and fails safely when blocked or corrupt', async (t) => {
  let cookie = '';
  let written = '';
  let blocked = false;
  t.after(() => {
    delete globalThis.document;
    delete globalThis.location;
  });
  globalThis.document = {
    get cookie() { return cookie; },
    set cookie(value) {
      written = value;
      if (!blocked) cookie = value.includes('Max-Age=0;') ? '' : value.split(';')[0];
    },
  };
  globalThis.location = { protocol: 'https:' };
  const first = loadAccount();
  assert.match(written, /Max-Age=31536000; SameSite=Strict; Secure$/);
  assert.match(cookie, new RegExp(`^${ACCOUNT_COOKIE}=[A-Za-z0-9_-]{43}$`));
  assert.equal(await loadAccount().thumbprint(), await first.thumbprint());
  clearAccount();
  assert.equal(cookie, '');
  blocked = true;
  assert.throws(() => loadAccount(), /Cookies are blocked/);
  blocked = false;
  cookie = `${ACCOUNT_COOKIE}=corrupt`;
  assert.throws(() => loadAccount(), /Invalid account cookie/);
});
