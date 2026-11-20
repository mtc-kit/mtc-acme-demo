import test from 'node:test';
import assert from 'node:assert/strict';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { accountFromSeed, base64url, decode64, generateCsr, parseCsr, parseDomains, sha256, utf8, pem, loadAccount, createAccount, clearAccount, ACCOUNT_COOKIE } from '../src/crypto.js';

test('ML-DSA-44/65/87 accounts restore from a compact seed and sign valid JOSE messages', async () => {
  for (const [alg, scheme] of [['ML-DSA-44', ml_dsa44], ['ML-DSA-65', ml_dsa65], ['ML-DSA-87', ml_dsa87]]) {
    const seed = crypto.getRandomValues(new Uint8Array(32));
    const first = accountFromSeed(seed, alg);
    const restored = accountFromSeed(decode64(base64url(seed)), alg);
    assert.deepEqual(restored.jwk, first.jwk);
    assert.deepEqual(Object.keys(first.jwk).sort(), ['alg', 'kty', 'pub']);
    assert.equal(first.jwk.alg, alg);
    assert.deepEqual(decode64(first.jwk.pub), scheme.keygen(seed).publicKey);
    const message = utf8('protected.payload');
    assert(scheme.verify(first.sign(message), message, decode64(first.jwk.pub)));
    assert.equal(await first.thumbprint(), base64url(await sha256(utf8(JSON.stringify({
      alg: first.jwk.alg, kty: first.jwk.kty, pub: first.jwk.pub,
    })))));
  }
  assert.throws(() => accountFromSeed(new Uint8Array(31), 'ML-DSA-65'));
  assert.throws(() => accountFromSeed(new Uint8Array(32), 'ES256'), /Unsupported account key algorithm/);
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
  const keyAlgorithm = readDer(spki.body);
  assert.equal(Buffer.from(keyAlgorithm.body).toString('hex'), '0609608648016503040311');
  assert.deepEqual(algorithm.body, keyAlgorithm.body);
  const publicKey = readDer(spki.body, keyAlgorithm.end).body.slice(1);
  assert(ml_dsa44.verify(signature.body.slice(1), info.full, publicKey));
  const pkcs8 = readDer(decode64(generated.privateKey.replace(/-----[^-]+-----|\s/g, '')));
  const pkcs8Version = readDer(pkcs8.body);
  const privateKeyAlgorithm = readDer(pkcs8.body, pkcs8Version.end);
  assert.deepEqual(privateKeyAlgorithm.body, keyAlgorithm.body);
  const seed = readDer(readDer(pkcs8.body, privateKeyAlgorithm.end).body);
  assert.equal(seed.tag, 0x80);
  assert.deepEqual(ml_dsa44.keygen(seed.body).publicKey, publicKey);
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

const classicalCsrs = {
  ecdsa: `-----BEGIN CERTIFICATE REQUEST-----
MIHGMG4CAQAwDDEKMAgGA1UEAwwBeDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IA
BHN01G4SSMLdNDMYtKzmCZmpKvM+DvOd45GuTfNR1mJaShsRnYDgD/LttPYpwnQQ
mK3Je7gChcLuN/oLthJGQ4qgADAKBggqhkjOPQQDAgNIADBFAiBHSxBzVOeNIWr3
n8iUZ+d254M3+AjZe1QyjnTMXuDGaAIhAMX/k/o1a4BrabVTbpswHhlgmSIKmYio
1pGqIWPZiR+o
-----END CERTIFICATE REQUEST-----`,
  ed25519: `-----BEGIN CERTIFICATE REQUEST-----
MIGLMD8CAQAwDDEKMAgGA1UEAwwBeDAqMAUGAytlcAMhAK53dXKf+ZCttRHWc7KV
5hQQjuubgmbihbdXURiOt9a8oAAwBQYDK2VwA0EAvuRERjwIpHbsJ+B+7LZBVtXp
/mk6JvZhxnLxYhVXTTQQyAVcxAKAwceU2snpfOIisnJyKqUwp1eWNJezxBuuCA==
-----END CERTIFICATE REQUEST-----`,
  rsa: `-----BEGIN CERTIFICATE REQUEST-----
MIIBSzCBtQIBADAMMQowCAYDVQQDDAF4MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCB
iQKBgQDuxUf3v0IrtepUTeq6UImoml6+pKVRLaT7GTS/CHPDPSnPNIDwVUlDkT2C
lnpqDB5CAabYtiKIwm1cB7athNfQDgUGSaGHeAaNK+dfW5e/RBE1oEa6W717lpSp
p5N/3RRw2ZrztOLZ0AxhYF6n+Z8pK+mPvfTK1sCKbctWm8pJ6wIDAQABoAAwDQYJ
KoZIhvcNAQELBQADgYEAlPmpprn1BBdXGmtJ/B0xqu8QShPf5pOgxfJX/vjCNLR/
LQCKHScc57T+ElC5W0TN3+3ptJNhWLZac6YE4eSUmd98ZwD2bygsjonAly4Fg9+f
cnp9LJqf1xnICFYy3VviJi+IhqWn6zXz93HnfqEEygctxYWKTKBBiukIcly7CnI=
-----END CERTIFICATE REQUEST-----`,
};

test('pasted CSRs must use a validly self-signed ML-DSA key', async () => {
  for (const [name, csr] of Object.entries(classicalCsrs)) {
    assert.throws(() => parseCsr(csr), /RSA, ECDSA, HashML-DSA, and other algorithms are not permitted/, name);
  }
  const generated = await generateCsr(['example.com']);
  const root = readDer(generated.der);
  const info = readDer(root.body);
  const signature = readDer(root.body, readDer(root.body, info.end).end);
  const withSignatureAlgorithm = (hex) => {
    const body = Buffer.concat([info.full, Buffer.from(hex, 'hex'), signature.full]);
    return pem('CERTIFICATE REQUEST', Buffer.concat([Buffer.from([0x30, 0x82, body.length >> 8, body.length & 255]), body]));
  };
  assert.deepEqual(parseCsr(withSignatureAlgorithm('300b0609608648016503040311')), generated.der);
  assert.throws(() => parseCsr(withSignatureAlgorithm('300b0609608648016503040312')), /must match its ML-DSA-44 key/);
  for (const [name, hex] of Object.entries({
    parameters: '300d06096086480165030403110500',
    nonMinimalLength: '30810b0609608648016503040311',
    hashMlDsa44: '300b0609608648016503040320',
  })) {
    assert.throws(() => parseCsr(withSignatureAlgorithm(hex)), /are not permitted/, name);
  }
  const tampered = generated.der.slice();
  tampered[tampered.length - 1] ^= 1;
  assert.throws(() => parseCsr(pem('CERTIFICATE REQUEST', tampered)), /signature is invalid/);
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
  assert.equal(loadAccount(), undefined);
  const first = createAccount('ML-DSA-87');
  assert.equal(first.jwk.alg, 'ML-DSA-87');
  assert.match(written, /Max-Age=31536000; SameSite=Strict; Secure$/);
  assert.match(cookie, new RegExp(`^${ACCOUNT_COOKIE}=ML-DSA-87\\.[A-Za-z0-9_-]{43}$`));
  const restored = loadAccount();
  assert.deepEqual(restored.jwk, first.jwk);
  assert.equal(await restored.thumbprint(), await first.thumbprint());
  const seed = cookie.split('.').at(-1);
  cookie = `${ACCOUNT_COOKIE}=${seed}`;
  assert.deepEqual(loadAccount().jwk, accountFromSeed(decode64(seed), 'ML-DSA-65').jwk, 'legacy seed-only cookie');
  clearAccount();
  assert.equal(cookie, '');
  blocked = true;
  assert.throws(() => createAccount('ML-DSA-44'), /Cookies are blocked/);
  blocked = false;
  for (const value of ['corrupt', `ML-DSA-99.${seed}`, `ES256.${seed}`]) {
    cookie = `${ACCOUNT_COOKIE}=${value}`;
    assert.throws(() => loadAccount(), /Invalid account cookie/, value);
  }
});
