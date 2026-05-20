import QRCode from 'qrcode';
import { splitQRs } from 'bbqr';
import { buildBip322Bundle } from './bip322.js';
import { spkToAddress } from './address.js';

// Anything up to this many base64 chars goes into a single plain QR. v15 at
// ECC M (77x77 modules) is robustly scannable on phone cameras and printed
// pages. Above this, switch to animated BBQr so we don't push the QR into a
// density that fails on poor scanners.
const PLAIN_QR_MAX_CHARS = 400;

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
  qrInfo: $('qr-info'),
};

let bbqrTimer = null;
let lastPsbtBytes = null;

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
    lastPsbtBytes = r.psbtBytes;
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

function stopBbqrAnimation() {
  if (bbqrTimer !== null) {
    clearInterval(bbqrTimer);
    bbqrTimer = null;
  }
}

function showQrError(msg) {
  stopBbqrAnimation();
  els.qr.hidden = true;
  els.qrInfo.hidden = true;
  els.qrNote.hidden = false;
  els.qrNote.textContent = msg;
}

function renderQr() {
  if (!els.psbt.value) return;
  stopBbqrAnimation();

  if (els.psbt.value.length <= PLAIN_QR_MAX_CHARS) {
    QRCode.toCanvas(
      els.qr,
      els.psbt.value,
      { errorCorrectionLevel: 'M', margin: 2, scale: 6 },
      (err) => {
        if (err) {
          showQrError('Failed to render QR: ' + err.message);
        } else {
          els.qr.hidden = false;
          els.qrNote.hidden = true;
          els.qrInfo.hidden = false;
          els.qrInfo.textContent = `Plain QR · ${els.psbt.value.length} base64 chars`;
        }
      },
    );
    return;
  }

  // Too big for a comfortable plain QR — switch to BBQr animated multi-part.
  renderBbqr();
}

async function renderBbqr() {
  try {
    const { parts, encoding, version } = await splitQRs(lastPsbtBytes, 'P', {
      encoding: 'Z',
    });
    if (!parts.length) {
      showQrError('BBQr produced no parts (unexpected).');
      return;
    }
    // splitQRs picks part sizes assuming ECC L (the densest mode). Render at
    // the version it planned for; pinning both keeps every frame the same
    // physical size so the animation doesn't jump.
    const opts = { errorCorrectionLevel: 'L', version, margin: 2, scale: 6 };
    let idx = 0;
    const draw = () => {
      QRCode.toCanvas(els.qr, parts[idx], opts, (err) => {
        if (err) showQrError('BBQr part failed to render: ' + err.message);
      });
      els.qrInfo.textContent =
        parts.length === 1
          ? `BBQr (encoding ${encoding}, v${version}) · single frame`
          : `BBQr (encoding ${encoding}, v${version}) · frame ${idx + 1} / ${parts.length}`;
      idx = (idx + 1) % parts.length;
    };
    draw();
    els.qr.hidden = false;
    els.qrNote.hidden = true;
    els.qrInfo.hidden = false;
    if (parts.length > 1) {
      bbqrTimer = setInterval(draw, 500);
    }
  } catch (e) {
    showQrError('Failed to build BBQr: ' + (e.message || String(e)));
  }
}

function toggleQr() {
  const expanded = els.toggleQr.getAttribute('aria-expanded') === 'true';
  const next = !expanded;
  els.toggleQr.setAttribute('aria-expanded', String(next));
  els.toggleQr.textContent = next ? 'Hide' : 'Show';
  els.qrBody.hidden = !next;
  if (next) renderQr();
  else stopBbqrAnimation();
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
