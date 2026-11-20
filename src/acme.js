import { base64url, decode64, utf8 } from './crypto.js';

export function endpoint(value) {
  const url = new URL(value);
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname))) {
    throw new Error('ACME URLs must use HTTPS (HTTP is allowed only on loopback for development).');
  }
  if (url.username || url.password || url.hash) throw new Error('ACME URLs cannot contain credentials or fragments.');
  return url.href;
}

export class AcmeClient {
  constructor(account, fetcher = fetch) {
    this.account = account;
    this.fetch = (url, options = {}) => fetcher(endpoint(url), {
      ...options, credentials: 'omit', cache: 'no-store', redirect: 'error',
      signal: AbortSignal.timeout(30000),
    });
  }

  async read(response) {
    this.nonce = response.headers.get('Replay-Nonce') || this.nonce;
    const text = await response.text();
    let data;
    try { data = JSON.parse(text); } catch { data = text; }
    if (!response.ok) {
      const error = new Error(data && typeof data === 'object'
        ? `${data.type || 'ACME error'}: ${data.detail || response.status}` : `HTTP ${response.status}: ${text.slice(0, 400)}`);
      error.type = data?.type;
      throw error;
    }
    return { data, response };
  }

  async connect(url) {
    const { data } = await this.read(await this.fetch(endpoint(url)));
    for (const field of ['newNonce', 'newAccount', 'newOrder']) endpoint(data[field]);
    this.directory = data;
    this.kid = undefined;
    return data;
  }

  async post(url, payload = null, useJwk = false, { raw = false, headers = {} } = {}) {
    for (let attempt = 0; attempt < 3; attempt++) {
      if (!this.nonce) {
        const response = await this.fetch(this.directory.newNonce, { method: 'HEAD' });
        await this.read(response);
        if (!this.nonce) throw new Error('Missing Replay-Nonce. Check the server’s CORS exposed headers.');
      }
      const nonce = this.nonce;
      this.nonce = undefined;
      const protectedHeader = {
        alg: this.account.jwk.alg, nonce, url: endpoint(url),
        ...(useJwk ? { jwk: this.account.jwk } : { kid: this.kid }),
      };
      if (!useJwk && !this.kid) throw new Error('Register the ACME account first.');
      const protected64 = base64url(utf8(JSON.stringify(protectedHeader)));
      const payload64 = payload === null ? '' : base64url(utf8(JSON.stringify(payload)));
      const signature = base64url(this.account.sign(utf8(`${protected64}.${payload64}`)));
      try {
        const response = await this.fetch(url, {
          method: 'POST',
          headers: { ...headers, 'Content-Type': 'application/jose+json' },
          body: JSON.stringify({ protected: protected64, payload: payload64, signature }),
        });
        if (raw && response.ok) {
          this.nonce = response.headers.get('Replay-Nonce') || this.nonce;
          return { response };
        }
        return await this.read(response);
      } catch (error) {
        if (!error.type?.endsWith(':badNonce') || attempt === 2) throw error;
      }
    }
  }

  async register(email, agree, eab) {
    const payload = { termsOfServiceAgreed: agree };
    if (email) payload.contact = [`mailto:${email}`];
    if (eab) payload.externalAccountBinding = await this.externalAccountBinding(eab);
    const { data, response } = await this.post(this.directory.newAccount, payload, true);
    const location = response.headers.get('Location');
    if (!location) throw new Error('Missing account Location. Check the server’s CORS exposed headers.');
    this.kid = endpoint(location);
    if (data.status !== 'valid') throw new Error(`Account is ${data.status}.`);
    return data;
  }

  // RFC 8555 §7.3.4: an HS256 JWS over the account JWK, keyed by the CA-issued MAC key.
  async externalAccountBinding({ kid, hmacKey }) {
    if (!kid) throw new Error('Enter the external account binding key ID.');
    let keyBytes;
    try { keyBytes = decode64(hmacKey.replace(/=+$/, '')); } catch { keyBytes = undefined; }
    if (!/^[A-Za-z0-9_-]+={0,2}$/.test(hmacKey) || !keyBytes?.length) {
      throw new Error('The external account binding HMAC key must be base64url-encoded.');
    }
    const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const protected64 = base64url(utf8(JSON.stringify({ alg: 'HS256', kid, url: this.directory.newAccount })));
    const payload64 = base64url(utf8(JSON.stringify(this.account.jwk)));
    const signature = new Uint8Array(await crypto.subtle.sign('HMAC', key, utf8(`${protected64}.${payload64}`)));
    return { protected: protected64, payload: payload64, signature: base64url(signature) };
  }

  async newOrder(domains) {
    const result = await this.post(this.directory.newOrder, {
      identifiers: domains.map((value) => ({ type: 'dns', value })),
    });
    const url = result.response.headers.get('Location');
    if (!url) throw new Error('Missing order Location. Check the server’s CORS exposed headers.');
    return { ...result.data, url: endpoint(url) };
  }

  async poll(url, done, onUpdate = () => {}) {
    const deadline = Date.now() + 180000;
    while (Date.now() < deadline) {
      const { data, response } = await this.post(url);
      onUpdate(data);
      if (['invalid', 'expired', 'revoked', 'deactivated'].includes(data.status)) {
        throw new Error(data.error?.detail || `ACME resource is ${data.status}.`);
      }
      if (done(data)) return data;
      const retry = response.headers.get('Retry-After');
      const seconds = retry && /^\d+$/.test(retry) ? Number(retry) : (Date.parse(retry) - Date.now()) / 1000;
      const delay = Math.max(1000, Number.isFinite(seconds) ? seconds * 1000 : 2000);
      if (Date.now() + delay >= deadline) break;
      await new Promise((resolve) => setTimeout(resolve, delay));
    }
    throw new Error('Polling timed out. Use “Refresh status” to resume this order.');
  }
}
