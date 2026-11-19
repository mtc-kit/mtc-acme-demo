import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

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

export function accountFromSeed(seed) {
  if (seed.length !== 32) throw new Error('The account seed must contain 32 bytes.');
  const { publicKey, secretKey } = ml_dsa65.keygen(seed);
  const jwk = { kty: 'AKP', alg: 'ML-DSA-65', pub: base64url(publicKey) };
  return {
    jwk,
    sign: (message) => ml_dsa65.sign(message, secretKey),
    // RFC 7638 canonical member ordering; alg is required for AKP thumbprints.
    thumbprint: async () => base64url(await sha256(utf8(JSON.stringify({
      alg: jwk.alg, kty: jwk.kty, pub: jwk.pub,
    })))),
  };
}

export function loadAccount() {
  const value = document.cookie.split('; ').find((part) => part.startsWith(`${ACCOUNT_COOKIE}=`))
    ?.slice(ACCOUNT_COOKIE.length + 1);
  if (value) {
    if (!/^[A-Za-z0-9_-]{43}$/.test(value)) {
      throw new Error('Invalid account cookie. Clear it explicitly to create a different account.');
    }
    return accountFromSeed(decode64(value));
  }
  const seed = crypto.getRandomValues(new Uint8Array(32));
  const encoded = base64url(seed);
  document.cookie = `${ACCOUNT_COOKIE}=${encoded}; Path=/; Max-Age=31536000; SameSite=Strict${location.protocol === 'https:' ? '; Secure' : ''}`;
  if (!document.cookie.split('; ').includes(`${ACCOUNT_COOKIE}=${encoded}`)) {
    throw new Error('Cookies are blocked. Allow first-party cookies to retain the ACME account.');
  }
  return accountFromSeed(seed);
}

export function clearAccount() {
  document.cookie = `${ACCOUNT_COOKIE}=; Path=/; Max-Age=0; SameSite=Strict${location.protocol === 'https:' ? '; Secure' : ''}`;
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

export function parseCsr(text) {
  const match = text.trim().match(/^-----BEGIN (?:NEW )?CERTIFICATE REQUEST-----\s+([A-Za-z0-9+/=\s]+)\s+-----END (?:NEW )?CERTIFICATE REQUEST-----$/);
  if (!match) throw new Error('Paste a PEM-encoded PKCS#10 certificate request.');
  const bytes = decode64(match[1].replace(/\s/g, ''));
  const count = bytes[1] < 128 ? 0 : bytes[1] & 0x7f;
  const header = bytes[1] < 128 ? 2 : 2 + count;
  const length = bytes[1] < 128 ? bytes[1]
    : bytes.slice(2, header).reduce((n, byte) => n * 256 + byte, 0);
  if (bytes[0] !== 0x30 || bytes[1] === 0x80 || count > 4 || header + length !== bytes.length) {
    throw new Error('The CSR is not a complete DER sequence.');
  }
  return bytes;
}

export async function generateCsr(domains) {
  const keys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const spki = new Uint8Array(await crypto.subtle.exportKey('spki', keys.publicKey));
  const san = sequence(...domains.map((name) => der(0x82, utf8(name))));
  const extension = sequence(oid([0x55, 0x1d, 0x11]), der(0x01, [0xff]), der(0x04, san));
  const attributes = der(0xa0, sequence(
    oid([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0e]),
    der(0x31, sequence(extension)),
  ));
  const info = sequence(der(0x02, [0]), sequence(), spki, attributes);
  const signature = new Uint8Array(await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' }, keys.privateKey, info,
  ));
  const integer = (part) => {
    let start = 0;
    while (start < part.length - 1 && part[start] === 0) start++;
    const value = part.slice(start);
    return der(0x02, ...(value[0] & 0x80 ? [[0], value] : [value]));
  };
  const signatureDer = sequence(integer(signature.slice(0, 32)), integer(signature.slice(32)));
  const csr = sequence(info, sequence(oid([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02])),
    der(0x03, [0], signatureDer));
  const privateKey = new Uint8Array(await crypto.subtle.exportKey('pkcs8', keys.privateKey));
  return { der: csr, csr: pem('CERTIFICATE REQUEST', csr), privateKey: pem('PRIVATE KEY', privateKey) };
}
