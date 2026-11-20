import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';

const encoder = new TextEncoder();
export const utf8 = (text) => encoder.encode(text);
export const ACCOUNT_COOKIE = 'mtc_acme_account_v1';

export function base64url(bytes) {
  return btoa(Array.from(bytes, (byte) => String.fromCharCode(byte)).join(''))
    .replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

export function decode64(text) {
  return Uint8Array.from(atob(text.replaceAll('-', '+').replaceAll('_', '/')), (c) => c.charCodeAt(0));
}

export async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

// RFC 9964 JOSE algorithm names for the permitted ACME account key types.
export const ACCOUNT_ALGORITHMS = { 'ML-DSA-44': ml_dsa44, 'ML-DSA-65': ml_dsa65, 'ML-DSA-87': ml_dsa87 };
// Cookies written before algorithm choice was added contain only an ML-DSA-65 seed.
const LEGACY_ACCOUNT_ALGORITHM = 'ML-DSA-65';

export function accountFromSeed(seed, alg) {
  if (!Object.hasOwn(ACCOUNT_ALGORITHMS, alg)) throw new Error(`Unsupported account key algorithm: ${alg}.`);
  if (seed.length !== 32) throw new Error('The account seed must contain 32 bytes.');
  const scheme = ACCOUNT_ALGORITHMS[alg];
  const { publicKey, secretKey } = scheme.keygen(seed);
  const jwk = { kty: 'AKP', alg, pub: base64url(publicKey) };
  return {
    jwk,
    sign: (message) => scheme.sign(message, secretKey),
    // RFC 7638 canonical member ordering; alg is required for AKP thumbprints.
    thumbprint: async () => base64url(await sha256(utf8(JSON.stringify({
      alg: jwk.alg, kty: jwk.kty, pub: jwk.pub,
    })))),
  };
}

const accountCookie = (value, maxAge) => `${ACCOUNT_COOKIE}=${value}; Path=/; Max-Age=${maxAge}; SameSite=Strict${location.protocol === 'https:' ? '; Secure' : ''}`;

export function loadAccount() {
  const value = document.cookie.split('; ').find((part) => part.startsWith(`${ACCOUNT_COOKIE}=`))
    ?.slice(ACCOUNT_COOKIE.length + 1);
  if (!value) return undefined;
  const match = value.match(/^(?:(ML-DSA-(?:44|65|87))\.)?([A-Za-z0-9_-]{43})$/);
  if (!match) throw new Error('Invalid account cookie. Clear it explicitly to create a different account.');
  return accountFromSeed(decode64(match[2]), match[1] ?? LEGACY_ACCOUNT_ALGORITHM);
}

export function createAccount(alg) {
  const seed = crypto.getRandomValues(new Uint8Array(32));
  const account = accountFromSeed(seed, alg);
  const value = `${alg}.${base64url(seed)}`;
  document.cookie = accountCookie(value, 31536000);
  if (!document.cookie.split('; ').includes(`${ACCOUNT_COOKIE}=${value}`)) {
    throw new Error('Cookies are blocked. Allow first-party cookies to retain the ACME account.');
  }
  return account;
}

export function clearAccount() {
  document.cookie = accountCookie('', 0);
}

export function parseDomains(text) {
  const domains = [...new Set(text.toLowerCase().split(/[\s,]+/).filter(Boolean))];
  if (!domains.length || domains.some((domain) => {
    const name = domain.replace(/^\*\./, '');
    return name.length > 253 || !name.includes('.') || name.split('.').some(
      (label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label),
    );
  })) throw new Error('Enter DNS names, separated by commas or whitespace. Use A-labels (xn--) for international names.');
  return domains;
}

const concat = (...parts) => new Uint8Array(parts.flatMap((part) => Array.from(part)));
function der(tag, ...parts) {
  const body = concat(...parts);
  const lengthBytes = [];
  for (let size = body.length; size > 0; size = Math.floor(size / 256)) {
    lengthBytes.unshift(size & 255);
  }
  const length = body.length < 128 ? [body.length] : [0x80 | lengthBytes.length, ...lengthBytes];
  return concat([tag, ...length], body);
}
const sequence = (...parts) => der(0x30, ...parts);
const oid = (bytes) => der(0x06, bytes);

export function pem(label, bytes) {
  const encoded = btoa(Array.from(bytes, (byte) => String.fromCharCode(byte)).join(''));
  return `-----BEGIN ${label}-----\n${encoded.match(/.{1,64}/g).join('\n')}\n-----END ${label}-----\n`;
}

// Chrome Quantum-resistant Root Program policy §2.4.3.2 permits these subscriber key
// AlgorithmIdentifiers (RFC 9881 pure ML-DSA, parameters absent), byte-for-byte.
const ML_DSA = [
  { name: 'ML-DSA-44', scheme: ml_dsa44, publicKeyLength: 1312 },
  { name: 'ML-DSA-65', scheme: ml_dsa65, publicKeyLength: 1952 },
  { name: 'ML-DSA-87', scheme: ml_dsa87, publicKeyLength: 2592 },
].map((algorithm, i) => ({
  ...algorithm,
  identifier: [0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11 + i],
}));
const GENERATED_ALGORITHM = ML_DSA[0];
const sameBytes = (a, b) => a.length === b.length && a.every((byte, i) => byte === b[i]);

function readDer(bytes, offset, end, tag, message = 'The CSR is not a well-formed PKCS#10 request.') {
  if (offset + 2 > end || bytes[offset] !== tag) throw new Error(message);
  let body = offset + 2;
  let length = bytes[offset + 1];
  if (length & 0x80) {
    const count = length & 0x7f;
    if (!count || count > 4 || body + count > end) throw new Error(message);
    length = bytes.slice(body, body + count).reduce((n, byte) => n * 256 + byte, 0);
    body += count;
  }
  if (body + length > end) throw new Error(message);
  return { start: offset, body, end: body + length };
}

function mlDsaAlgorithm(bytes, identifier) {
  const encoded = bytes.slice(identifier.start, identifier.end);
  const algorithm = ML_DSA.find((candidate) => sameBytes(encoded, candidate.identifier));
  if (!algorithm) {
    throw new Error('The CSR must use an ML-DSA-44, ML-DSA-65, or ML-DSA-87 key and signature with a DER-encoded AlgorithmIdentifier without parameters; RSA, ECDSA, HashML-DSA, and other algorithms are not permitted.');
  }
  return algorithm;
}

export function parseCsr(text) {
  const match = text.trim().match(/^-----BEGIN (?:NEW )?CERTIFICATE REQUEST-----\s+([A-Za-z0-9+/=\s]+)\s+-----END (?:NEW )?CERTIFICATE REQUEST-----$/);
  if (!match) throw new Error('Paste a PEM-encoded PKCS#10 certificate request.');
  const bytes = decode64(match[1].replace(/\s/g, ''));
  const root = readDer(bytes, 0, bytes.length, 0x30, 'The CSR is not a complete DER sequence.');
  if (root.end !== bytes.length) throw new Error('The CSR is not a complete DER sequence.');
  const info = readDer(bytes, root.body, root.end, 0x30);
  const signatureAlgorithm = readDer(bytes, info.end, root.end, 0x30);
  const signature = readDer(bytes, signatureAlgorithm.end, root.end, 0x03);
  const version = readDer(bytes, info.body, info.end, 0x02);
  const subject = readDer(bytes, version.end, info.end, 0x30);
  const spki = readDer(bytes, subject.end, info.end, 0x30);
  const keyAlgorithm = readDer(bytes, spki.body, spki.end, 0x30);
  const publicKey = readDer(bytes, keyAlgorithm.end, spki.end, 0x03);
  if (signature.end !== root.end || publicKey.end !== spki.end
    || bytes[signature.body] !== 0 || bytes[publicKey.body] !== 0) {
    throw new Error('The CSR is not a well-formed PKCS#10 request.');
  }
  const algorithm = mlDsaAlgorithm(bytes, keyAlgorithm);
  if (mlDsaAlgorithm(bytes, signatureAlgorithm) !== algorithm) {
    throw new Error(`The CSR signature algorithm must match its ${algorithm.name} key.`);
  }
  const key = bytes.slice(publicKey.body + 1, publicKey.end);
  if (key.length !== algorithm.publicKeyLength) {
    throw new Error(`The CSR contains an invalid ${algorithm.name} public key.`);
  }
  if (!algorithm.scheme.verify(bytes.slice(signature.body + 1, signature.end), bytes.slice(info.start, info.end), key)) {
    throw new Error('The CSR signature is invalid.');
  }
  return bytes;
}

export async function generateCsr(domains) {
  const algorithm = GENERATED_ALGORITHM;
  const seed = crypto.getRandomValues(new Uint8Array(32));
  const { publicKey, secretKey } = algorithm.scheme.keygen(seed);
  const algorithmIdentifier = new Uint8Array(algorithm.identifier);
  const spki = sequence(algorithmIdentifier, der(0x03, [0], publicKey));
  const san = sequence(...domains.map((name) => der(0x82, utf8(name))));
  const extension = sequence(oid([0x55, 0x1d, 0x11]), der(0x01, [0xff]), der(0x04, san));
  const attributes = der(0xa0, sequence(
    oid([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0e]),
    der(0x31, sequence(extension)),
  ));
  const info = sequence(der(0x02, [0]), sequence(), spki, attributes);
  const signature = algorithm.scheme.sign(info, secretKey);
  const csr = sequence(info, algorithmIdentifier, der(0x03, [0], signature));
  // RFC 9881 seed-only ML-DSA-PrivateKey: [0] IMPLICIT OCTET STRING (SIZE (32)).
  const privateKey = sequence(der(0x02, [0]), algorithmIdentifier, der(0x04, der(0x80, seed)));
  return { der: csr, csr: pem('CERTIFICATE REQUEST', csr), privateKey: pem('PRIVATE KEY', privateKey) };
}
