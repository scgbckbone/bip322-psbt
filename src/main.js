import { buildBip322Bundle } from './bip322.js';
import { spkToAddress } from './address.js';

const $ = (id) => document.getElementById(id);

const els = {
  message: $('message'),
  descriptor: $('descriptor'),
  build: $('build'),
  example: $('example'),
  copy: $('copy'),
  psbt: $('psbt'),
  network: $('network'),
  type: $('type'),
  address: $('address'),
  output: $('output'),
  status: $('status'),
  error: $('error'),
};

// Mainnet wpkh derived from the Coinkite simulator's known xpub. Same key
// the test fixtures use, so the resulting PSBT is one anyone with the repo
// can reproduce locally.
const EXAMPLE = {
  message: 'POR',
  descriptor:
    'wpkh([0f056943]xpub661MyMwAqRbcGC9DmWbtbAmuUjpMYxw4BWE88NSDHB3jSjfUK7KtYJuKa52GbowD3DVLkgsxH9QwPnTx5mjdHykYFEncnmAsNsCTbWzBhA7/0/0)',
};

function showError(msg) {
  els.error.hidden = false;
  els.error.textContent = msg;
  els.output.hidden = true;
  els.status.textContent = '';
}

function clearError() {
  els.error.hidden = true;
  els.error.textContent = '';
}

function build() {
  clearError();
  const message = els.message.value;
  const descriptor = els.descriptor.value.trim();
  if (!descriptor) {
    showError('Paste an output descriptor.');
    return;
  }
  try {
    const r = buildBip322Bundle({ message, descriptor });
    els.psbt.value = r.psbtBase64;
    els.network.textContent = r.network;
    els.type.textContent = r.type;
    els.address.value = spkToAddress(r.scriptPubKey, r.network) ?? '(unknown)';
    els.output.hidden = false;
    els.status.textContent = '';
  } catch (e) {
    showError(e.message || String(e));
  }
}

function loadExample() {
  els.message.value = EXAMPLE.message;
  els.descriptor.value = EXAMPLE.descriptor;
  build();
}

async function copy() {
  if (!els.psbt.value) return;
  try {
    await navigator.clipboard.writeText(els.psbt.value);
    els.status.textContent = 'Copied to clipboard.';
    setTimeout(() => (els.status.textContent = ''), 1500);
  } catch {
    els.psbt.select();
    document.execCommand('copy');
    els.status.textContent = 'Copied.';
    setTimeout(() => (els.status.textContent = ''), 1500);
  }
}

els.build.addEventListener('click', build);
els.example.addEventListener('click', loadExample);
els.copy.addEventListener('click', copy);

for (const t of [els.message, els.descriptor]) {
  t.addEventListener('keydown', (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
      e.preventDefault();
      build();
    }
  });
}
