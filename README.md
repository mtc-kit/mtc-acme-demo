# MTC ACME browser demo

A static, browser-only RFC 8555 ACME client for experimental Merkle Tree
Certificate (MTC) servers. There is no application backend or ACME proxy.

## Run

Use Node.js 22.12 or newer:

```sh
npm ci
npm run dev
```

Open the displayed localhost URL. For deployment, run `npm run build` and serve
`dist/` from a **dedicated, trusted HTTPS origin**. Do not open `index.html` using
`file://`. `npm run preview` previews a production build; `npm test` runs the
built-in Node crypto and protocol tests.

## Request a certificate

1. The webpage creates an **ML-DSA-65** account key using
   `@noble/post-quantum`. Its 32-byte private seed is stored in the
   `mtc_acme_account_v1` first-party cookie for one year. Reloading on the same
   origin restores the key; connecting and registering again resumes the same
   server account.
2. Replace `https://acme.mtc.example/directory` with your server's directory URL
   and select **Connect**. The default is deliberately fictional.
3. Enter DNS names, optionally an account email, and choose a CSR mode:
   - **Generate:** creates a separate ECDSA P-256 certificate key and PKCS#10
     CSR with DNS subject alternative names, locally with Web Crypto.
     **Download the private key before leaving or reloading the page.**
   - **Paste:** accepts a PEM PKCS#10 CSR. List exactly the DNS names in its SAN
     extension. Keep its private key yourself. The CA validates the CSR and
     identifier match; the webpage only checks the PEM/DER envelope.
4. Read and accept the connected server's terms, then place an order.
5. Provision one offered challenge per authorization: publish the displayed
   `dns-01` TXT record or serve the exact `http-01` body. Select **validate**
   only after provisioning. Wildcards require DNS validation.
6. Once the order is ready, select **Finalize & retrieve certificate**.
   The certificate response is downloaded without changing its bytes.

Validation and issuance polling honor `Retry-After`, with a three-minute
waiting limit and 30-second per-request timeout. Use **Refresh status** and
finalize again after a timeout. Orders, generated certificate keys, and
certificates are kept only in page memory, not persisted across reloads.
If you forget the account cookie, the app cannot recover the old account.

## MTC interoperability

- The ACME server must accept ML-DSA-65 JOSE accounts. The client uses
  [RFC 9964](https://www.rfc-editor.org/rfc/rfc9964.html) public JWKs
  (`kty: "AKP"`, `alg: "ML-DSA-65"`, `pub`) and ordinary ML-DSA with an empty
  context. No account private key material is sent to the ACME server.
- MTC support does not imply support for ML-DSA account keys. A conventional
  ACME server may reject this algorithm; the client deliberately does not
  fall back to a classical account key.
- Certificate keys are independent of account keys. The generated P-256
  certificate key is **not post-quantum**. Paste a CSR with a different
  server-supported key type if required by the server's MTC profile.
- Certificate POST-as-GET requests advertise
  `application/pem-certificate-chain-with-properties` and, as a fallback,
  `application/pem-certificate-chain`. MTC responses may contain a
  `CERTIFICATE PROPERTIES` block in addition to certificates, or use another
  experimental format. Downloads preserve the entire response as
  `certificate-response.bin`; use the displayed Content-Type to interpret it.
- The app retrieves the primary, standalone certificate. It does not retrieve
  delayed landmark-relative `acme-optional-alternate` links, select ACME
  profiles, or verify MTC proofs. An MTC-aware consumer is needed to validate
  the resulting certificate.
- Manual `dns-01` and `http-01` are supported. External account binding,
  `tls-alpn-01`, revocation, and automated renewal are not implemented.
  Draft-based MTC servers may have additional interoperability requirements.

### Browser CORS requirements

Every ACME endpoint (including authorization and certificate URLs) must allow
the webpage's origin via `Access-Control-Allow-Origin`. Support `GET`, `HEAD`,
and `POST`, handle `OPTIONS` preflights, and allow the `Content-Type` request
header (`application/jose+json`). Expose these response headers on **both
success and error responses**:

```http
Access-Control-Expose-Headers: Replay-Nonce, Location, Retry-After, Link
```

The client uses credential-free requests and refuses redirects. All ACME
endpoints must use HTTPS, except HTTP loopback URLs for local development.
The host's Content Security Policy, if any, must allow connections to your CA.

## Security limitations

This is a demo, not a production key vault. The account seed cookie is
JavaScript-readable by design, uses `SameSite=Strict`, and uses `Secure` on
HTTPS. It cannot be `HttpOnly` because the webpage must read it. Cookies are
also sent to the webpage's host, and any same-origin script or XSS could steal
the account key. Use a dedicated origin, trust its operator, avoid third-party
scripts, and use only disposable test accounts. Do not put real account
cookies or certificate keys in bug reports. **Forget account** deletes the
local cookie; it does not deactivate the server account or revoke certificates.

ACME payloads and server messages are rendered as text, not HTML. Keys,
CSR generation, and signing run locally; only public account data, contact
information, requested names, CSRs, and signed protocol messages are sent to
the selected CA. There is no telemetry, CDN dependency, or runtime remote
script loading.