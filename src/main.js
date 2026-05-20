import QRCode from 'qrcode';
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
  quorum: $('quorum'),
  quorumWrap: $('quorum-wrap'),
  address: $('address'),
  output: $('output'),
  status: $('status'),
  error: $('error'),
  toggleQr: $('toggle-qr'),
  qrBody: $('qr-body'),
  qr: $('qr'),
  qrNote: $('qr-note'),
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
    els.type.textContent = r.type + (r.sorted ? ' (sortedmulti)' : r.m ? ' (multi)' : '');
    if (r.m && r.n) {
      els.quorum.textContent = `${r.m} of ${r.n}`;
      els.quorumWrap.hidden = false;
    } else {
      els.quorumWrap.hidden = true;
    }
    els.address.value = spkToAddress(r.scriptPubKey, r.network) ?? '(unknown)';
    els.output.hidden = false;
    els.status.textContent = '';
    if (els.toggleQr.getAttribute('aria-expanded') === 'true') {
      renderQr();
    }
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

function renderQr() {
  if (!els.psbt.value) return;
  QRCode.toCanvas(
    els.qr,
    els.psbt.value,
    { errorCorrectionLevel: 'L', margin: 0, scale: 4 },
    (err) => {
      if (err) {
        els.qr.hidden = true;
        els.qrNote.hidden = false;
        els.qrNote.textContent =
          'PSBT is too large for a single QR code — copy the base64 instead.';
      } else {
        els.qr.hidden = false;
        els.qrNote.hidden = true;
      }
    },
  );
}

function toggleQr() {
  const expanded = els.toggleQr.getAttribute('aria-expanded') === 'true';
  const next = !expanded;
  els.toggleQr.setAttribute('aria-expanded', String(next));
  els.toggleQr.textContent = next ? 'Hide' : 'Show';
  els.qrBody.hidden = !next;
  if (next) renderQr();
}

els.build.addEventListener('click', build);
els.example.addEventListener('click', loadExample);
els.copy.addEventListener('click', copy);
els.toggleQr.addEventListener('click', toggleQr);

for (const t of [els.message, els.descriptor]) {
  t.addEventListener('keydown', (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
      e.preventDefault();
      build();
    }
  });
}
