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
`dist/` from a **dedicated, trusted HTTPS origin**. The build uses relative asset
paths, so it can be served from any directory. Do not open `index.html` using
`file://`. `npm run preview` previews a production build; `npm test` runs the
built-in Node crypto and protocol tests.

### GitHub Pages

[`.github/workflows/pages.yml`](.github/workflows/pages.yml) tests and builds
every push and pull request, and deploys `main` to
<https://mtc-kit.github.io/mtc-acme-demo/>. The repository's Pages source must
be set to **GitHub Actions**. ACME servers must allow CORS requests from
`https://mtc-kit.github.io`.

The `mtc-kit.github.io` origin is shared by every Pages site in the `mtc-kit`
organization, so scripts on any of them can read this app's account cookie.
For anything beyond disposable test accounts, configure a dedicated custom
domain for the Pages site.

## Request a certificate

1. On first visit, choose an **ML-DSA-44**, **ML-DSA-65** (default), or
   **ML-DSA-87** account key and select **Create account key**. The key is
   generated using `@noble/post-quantum`. The algorithm and 32-byte private
   seed are stored in the `mtc_acme_account_v1` first-party cookie for one
   year. Reloading on the same origin restores the key; connecting and
   registering again resumes the same server account. To use a different
   algorithm, select **Forget account** and create a new key. Cookies written
   by earlier versions, which hold only a seed, are restored as ML-DSA-65.
2. Replace `https://acme.mtc.example/directory` with your server's directory URL
   and select **Connect**. The default is deliberately fictional.
3. Enter DNS names, optionally an account email, and choose a CSR mode. If the
   directory requires external account binding (EAB), also enter the EAB key
   ID and HMAC key issued by your CA:
   - **Generate:** creates a separate ML-DSA-44 certificate key and PKCS#10
     CSR with DNS subject alternative names, locally in the browser. The key
     is downloaded as a seed-only PKCS#8 file
     ([RFC 9881](https://www.rfc-editor.org/rfc/rfc9881.html)).
     **Download the private key before leaving or reloading the page.**
   - **Paste:** accepts a PEM PKCS#10 CSR with an ML-DSA-44, ML-DSA-65, or
     ML-DSA-87 key, as permitted for Subscriber certificates by the
     [Chrome Quantum-resistant Root Program policy](https://googlechrome.github.io/chromerootprogram/cqrp/draft-policy/)
     (§2.4.3.2). The key and signature AlgorithmIdentifiers must be
     byte-for-byte the policy's encodings (pure ML-DSA, parameters absent).
     RSA, ECDSA, EdDSA, HashML-DSA, and all other key types are rejected.
     List exactly the DNS names in its SAN extension. Keep its private key
     yourself. The webpage checks the key and signature algorithms and the
     CSR's self-signature; the CA validates the CSR and identifier match.
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

- The ACME server must accept JOSE accounts using the chosen ML-DSA
  algorithm. The client uses
  [RFC 9964](https://www.rfc-editor.org/rfc/rfc9964.html) public JWKs
  (`kty: "AKP"`, `alg: "ML-DSA-44"`, `"ML-DSA-65"`, or `"ML-DSA-87"`, `pub`),
  the same `alg` in the JWS protected header, and ordinary ML-DSA with an
  empty context. No account private key material is sent to the ACME server.
- MTC support does not imply support for ML-DSA account keys. A conventional
  ACME server may reject this algorithm; the client deliberately does not
  fall back to a classical account key.
- Certificate keys are independent of account keys, but must also be ML-DSA.
  The server's MTC profile must accept ML-DSA certificate keys; the client
  deliberately does not permit classical certificate keys.
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
- Manual `dns-01` and `http-01` are supported. `tls-alpn-01`, revocation, and
  automated renewal are not implemented.
  Draft-based MTC servers may have additional interoperability requirements.
- External account binding
  ([RFC 8555 §7.3.4](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.3.4))
  is supported with HS256 and a base64url-encoded HMAC key. The EAB fields
  are shown, and the binding is sent, only when the directory sets
  `meta.externalAccountRequired` to `true`. The HMAC key is used only in the
  page to sign the binding; it is not sent to the CA or stored.

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