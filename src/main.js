import './style.css';
import { AcmeClient, endpoint } from './acme.js';
import { loadAccount, clearAccount, parseDomains, generateCsr, parseCsr, sha256, utf8, base64url } from './crypto.js';

const $ = (id) => document.getElementById(id);
let account;
let client;
let order;
let csr;
let generated;
let certificate;
let busy = false;

function download(name, data, type = 'application/octet-stream') {
  const url = URL.createObjectURL(new Blob([data], { type }));
  const link = document.createElement('a');
  link.href = url;
  link.download = name;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function controls() {
  document.querySelectorAll('button, input, textarea').forEach((element) => {
    element.disabled = busy || element.dataset.invalid === 'true';
  });
  $('start-order').disabled = busy || !client?.directory || !account;
  $('finalize').disabled = busy || !order || !['ready', 'processing', 'valid'].includes(order.status);
}

async function run(message, action) {
  if (busy) return;
  busy = true;
  $('error').hidden = true;
  $('activity').textContent = message;
  controls();
  try {
    await action();
    $('activity').textContent = 'Ready.';
  } catch (error) {
    $('activity').textContent = '';
    $('error').textContent = `${error.message} If a network request failed, check the URL, TLS, and the server’s CORS configuration.`;
    $('error').hidden = false;
  } finally {
    busy = false;
    controls();
  }
}

function showOrder() {
  $('issuance').hidden = false;
  $('order-status').textContent = `Order: ${order.status} — ${order.url}`;
}

function addText(parent, tag, text) {
  const element = document.createElement(tag);
  element.textContent = text;
  parent.append(element);
  return element;
}

async function renderAuthorizations() {
  $('challenges').replaceChildren();
  for (const url of order.authorizations || []) {
    const { data: auth } = await client.post(url);
    const card = document.createElement('article');
    $('challenges').append(card);
    const domain = auth.identifier?.value;
    addText(card, 'h3', `${auth.wildcard ? '*.' : ''}${domain} — ${auth.status}`);
    if (auth.status === 'valid') continue;
    if (auth.status !== 'pending') {
      addText(card, 'p', auth.error?.detail || 'Authorization is not pending. Place a new order if it cannot be resumed.');
      continue;
    }
    let supported = false;
    for (const challenge of auth.challenges || []) {
      if (!['dns-01', 'http-01'].includes(challenge.type)) continue;
      if (auth.wildcard && challenge.type !== 'dns-01') continue;
      if (!/^[A-Za-z0-9_-]+$/.test(challenge.token)) throw new Error('The server returned an invalid challenge token.');
      supported = true;
      const box = document.createElement('div');
      card.append(box);
      addText(box, 'h4', challenge.type);
      const keyAuthorization = `${challenge.token}.${await account.thumbprint()}`;
      if (challenge.type === 'dns-01') {
        addText(box, 'p', `Create a TXT record at _acme-challenge.${domain}:`);
        addText(box, 'pre', base64url(await sha256(utf8(keyAuthorization))));
        addText(box, 'p', 'Wait for DNS propagation before validating. Keep all required TXT values when names share a record.');
      } else {
        addText(box, 'p', `Serve this exact body at http://${domain}/.well-known/acme-challenge/${challenge.token}:`);
        addText(box, 'pre', keyAuthorization);
      }
      if (challenge.error) addText(box, 'p', challenge.error.detail || JSON.stringify(challenge.error));
      const button = addText(box, 'button', `I’ve provisioned ${challenge.type} — validate`);
      button.type = 'button';
      button.disabled = challenge.status === 'invalid';
      button.dataset.invalid = String(challenge.status === 'invalid');
      button.addEventListener('click', () => run('Waiting for authorization validation…', async () => {
        await client.post(challenge.url, {});
        await client.poll(url, (value) => value.status === 'valid');
        await refresh();
      }));
    }
    if (!supported) addText(card, 'p', 'No supported challenge offered. This demo supports manual dns-01 and http-01.');
  }
}

async function refresh() {
  const { data } = await client.post(order.url);
  order = { ...data, url: order.url };
  showOrder();
  await renderAuthorizations();
  if (order.error) throw new Error(order.error.detail || JSON.stringify(order.error));
}

$('directory-form').addEventListener('submit', (event) => {
  event.preventDefault();
  run('Loading directory…', async () => {
    client = undefined;
    order = undefined;
    $('issuance').hidden = true;
    $('terms').hidden = true;
    $('agree').checked = false;
    $('directory-status').textContent = 'Not connected.';
    const next = new AcmeClient(account);
    const url = endpoint($('directory').value.trim());
    const directory = await next.connect(url);
    if (directory.meta?.externalAccountRequired) {
      throw new Error('This directory requires external account binding, which this demo does not support.');
    }
    if (directory.meta?.termsOfService) {
      $('terms-link').href = endpoint(directory.meta.termsOfService);
      $('terms').hidden = false;
    }
    client = next;
    $('directory-status').textContent = `Connected to ${url}`;
  });
});

document.querySelectorAll('[name="csr-mode"]').forEach((input) => {
  input.addEventListener('change', () => {
    const paste = document.querySelector('[name="csr-mode"]:checked').value === 'paste';
    $('paste-panel').hidden = !paste;
    $('csr-input').required = paste;
  });
});

$('order-form').addEventListener('submit', (event) => {
  event.preventDefault();
  run('Preparing CSR and placing order…', async () => {
    if (!$('agree').checked) throw new Error('Read and accept the connected server’s terms before creating an account.');
    if (order && !confirm('Replace the current order in this page? Save any generated certificate private key first.')) return;
    const domains = parseDomains($('domains').value);
    if (document.querySelector('[name="csr-mode"]:checked').value === 'paste') {
      csr = parseCsr($('csr-input').value);
      generated = undefined;
    } else {
      generated = await generateCsr(domains);
      csr = generated.der;
    }
    $('generated').hidden = !generated;
    order = undefined;
    $('issuance').hidden = true;
    $('certificate').hidden = true;
    await client.register($('email').value.trim(), $('agree').checked);
    order = await client.newOrder(domains);
    await refresh();
  });
});

$('refresh').addEventListener('click', () => run('Refreshing order…', refresh));
$('finalize').addEventListener('click', () => run('Finalizing and waiting for issuance…', async () => {
  await refresh();
  if (order.status === 'ready') {
    const { data } = await client.post(order.finalize, { csr: base64url(csr) });
    order = { ...data, url: order.url };
    showOrder();
  }
  if (!['processing', 'valid'].includes(order.status)) throw new Error(`Order is ${order.status}; complete authorizations and refresh first.`);
  const result = await client.poll(order.url, (value) => value.status === 'valid', (value) => {
    order = { ...value, url: order.url };
    showOrder();
  });
  if (!result.certificate) throw new Error('Valid order has no certificate URL.');
  // Keep the response binary-safe: experimental MTC servers need not return PEM.
  const { response } = await client.post(result.certificate, null, false, {
    raw: true,
    headers: { Accept: 'application/pem-certificate-chain-with-properties, application/pem-certificate-chain;q=0.9' },
  });
  if (response.status !== 200) throw new Error(`Certificate response is HTTP ${response.status}. Try retrieving it again later.`);
  certificate = await response.blob();
  $('certificate-type').textContent = `Content-Type: ${certificate.type || 'unspecified'} · ${certificate.size} bytes`;
  $('certificate').hidden = false;
}));

$('download-key').addEventListener('click', () => download('certificate-key.pem', generated.privateKey, 'application/pkcs8'));
$('download-csr').addEventListener('click', () => download('request.csr.pem', generated.csr, 'application/pkcs10'));
$('download-certificate').addEventListener('click', () => download('certificate-response.bin', certificate));
$('reset-account').addEventListener('click', () => {
  if (confirm('Forget the account key? You will lose access to this account unless you saved its cookie seed.')) {
    clearAccount();
    location.reload();
  }
});

run('Loading local ML-DSA account…', async () => {
  if (!window.isSecureContext || !crypto.subtle) throw new Error('Open this app over HTTPS or localhost.');
  account = loadAccount();
  $('account-status').textContent = `ML-DSA-65 · Account thumbprint: ${await account.thumbprint()}`;
});
