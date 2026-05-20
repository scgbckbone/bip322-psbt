import QRCode from 'qrcode';
import { splitQRs } from 'bbqr';
import { buildBip322Bundle } from './bip322.js';
import { spkToAddress } from './address.js';

const $ = (id) => document.getElementById(id);

const els = {
  message: $('message'),
  descriptor: $('descriptor'),
  build: $('build'),
  example: $('example'),
  copy: $('copy'),
  download: $('download'),
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
  qrCompress: $('qr-compress'),
  scan: $('scan'),
  scanModal: $('scan-modal'),
  scanClose: $('scan-close'),
  scanVideo: $('scan-video'),
  scanStatus: $('scan-status'),
};

let bbqrTimer = null;
let lastPsbtBytes = null;

function getFormat() {
  return document.querySelector('input[name="qr-format"]:checked')?.value ?? 'bbqr';
}

function getUtxoChoice() {
  return document.querySelector('input[name="utxo-format"]:checked')?.value ?? 'witness';
}

function setUtxoChoice(value) {
  const radio = document.querySelector(`input[name="utxo-format"][value="${value}"]`);
  if (radio) radio.checked = true;
}

// Mainnet wpkh keyed off the same xpub the test fixtures use, so the
// resulting PSBT is one anyone with the repo can reproduce locally. The
// message names the very address the descriptor derives, so the example
// also doubles as a worked check of the 'Address being proved' field.
const EXAMPLE = {
  message: 'I control this address bc1qpvjn0f7k70xxdry7n7srq0lm8jkkaxupfk25ew !!',
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

// `auto` means: let buildBip322Bundle pick the appropriate utxo type for the
// parsed script, then sync the radio to whatever was used. After the first
// Build, subsequent clicks honor whatever the radio currently shows so the
// user's manual choice sticks.
// When the user edits the inputs after a Build, the on-screen output (PSBT,
// address, QR, Copy/Download targets) no longer matches what's in the form.
// Hiding the output panel and clearing lastPsbtBytes prevents stale data
// from being copied / downloaded / scanned silently.
function invalidateOutput() {
  if (!els.output.hidden) {
    els.output.hidden = true;
    els.psbt.value = '';
    lastPsbtBytes = null;
    stopBbqrAnimation();
    els.toggleQr.setAttribute('aria-expanded', 'false');
    els.toggleQr.textContent = 'Show';
    els.qrBody.hidden = true;
  }
}

function build(auto = true) {
  clearError();
  const message = els.message.value;
  const descriptor = els.descriptor.value.trim();
  if (!descriptor) {
    showError('Paste an output descriptor.');
    return;
  }
  try {
    const r = buildBip322Bundle({
      message,
      descriptor,
      utxoType: auto ? undefined : getUtxoChoice(),
    });
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
    setUtxoChoice(r.utxoType);
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

function download() {
  if (!lastPsbtBytes) return;
  const blob = new Blob([lastPsbtBytes], { type: 'application/octet-stream' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `bip322-${stamp()}.psbt`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  els.status.textContent = `Saved ${a.download}`;
  setTimeout(() => (els.status.textContent = ''), 1800);
}

function stamp() {
  const d = new Date();
  const pad = (n) => String(n).padStart(2, '0');
  return (
    d.getFullYear().toString() +
    pad(d.getMonth() + 1) +
    pad(d.getDate()) +
    'T' +
    pad(d.getHours()) +
    pad(d.getMinutes()) +
    pad(d.getSeconds())
  );
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
  if (getFormat() === 'plain') renderPlain();
  else renderBbqr();
}

function renderPlain() {
  QRCode.toCanvas(
    els.qr,
    els.psbt.value,
    { errorCorrectionLevel: 'M', margin: 2, scale: 5 },
    (err) => {
      if (err) {
        if (/too big|too large|amount of data/i.test(err.message)) {
          showQrError(
            `Plain QR cannot hold ${els.psbt.value.length} base64 chars — switch the Format toggle above to BBQr.`,
          );
        } else {
          showQrError('Failed to render QR: ' + err.message);
        }
      } else {
        els.qr.hidden = false;
        els.qrNote.hidden = true;
        els.qrInfo.hidden = false;
        els.qrInfo.textContent = `Plain QR · ${els.psbt.value.length} base64 chars`;
      }
    },
  );
}

async function renderBbqr() {
  try {
    // Cap each part at QR v20 (97x97 modules, ~485 px at scale 5) so individual
    // frames stay scannable on phone cameras. splitQRs will produce more frames
    // for larger payloads rather than packing them into one massive QR.
    // 'Z' = zstd+base32, '2' = plain base32 (no compression).
    const requestedEncoding = els.qrCompress.checked ? 'Z' : '2';
    const { parts, encoding, version } = await splitQRs(lastPsbtBytes, 'P', {
      encoding: requestedEncoding,
      maxVersion: 20,
    });
    if (!parts.length) {
      showQrError('BBQr produced no parts (unexpected).');
      return;
    }
    // splitQRs picks part sizes assuming ECC L (the densest mode). Render at
    // the version it planned for; pinning both keeps every frame the same
    // physical size so the animation doesn't jump.
    const opts = { errorCorrectionLevel: 'L', version, margin: 2, scale: 5 };
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

function syncCompressEnabled() {
  const plain = getFormat() === 'plain';
  els.qrCompress.disabled = plain;
  els.qrCompress.parentElement?.setAttribute('aria-disabled', String(plain));
}

function onFormatChange() {
  syncCompressEnabled();
  if (!els.qrBody.hidden && els.psbt.value) renderQr();
}

function onCompressChange() {
  if (!els.qrBody.hidden && els.psbt.value && getFormat() === 'bbqr') renderQr();
}

for (const radio of document.querySelectorAll('input[name="qr-format"]')) {
  radio.addEventListener('change', onFormatChange);
}
els.qrCompress.addEventListener('change', onCompressChange);
syncCompressEnabled();

// Changing the utxo radio after a Build re-runs the build using the user's
// explicit choice — preserves Copy/Download targets in lockstep with the QR.
for (const radio of document.querySelectorAll('input[name="utxo-format"]')) {
  radio.addEventListener('change', () => {
    if (els.descriptor.value.trim() && !els.output.hidden) build(false);
  });
}

// --- QR scanner (webcam, single-shot) ---
// jsQR is loaded on demand so the initial bundle stays small for users who
// never click 'Scan QR'.

let scanStream = null;
let scanCanvas = null;
let scanRafId = null;
let jsQR = null;

async function openScan() {
  if (!navigator.mediaDevices?.getUserMedia) {
    showError(
      'Camera access not supported in this browser. Paste the descriptor manually.',
    );
    return;
  }
  els.scanModal.hidden = false;
  els.scanStatus.textContent = 'Loading decoder…';
  if (!jsQR) {
    try {
      ({ default: jsQR } = await import('jsqr'));
    } catch (e) {
      els.scanStatus.textContent = 'Failed to load QR decoder: ' + (e?.message || e);
      return;
    }
  }
  els.scanStatus.textContent = 'Requesting camera…';
  try {
    scanStream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: 'environment' },
      audio: false,
    });
  } catch (e) {
    els.scanStatus.textContent =
      e?.name === 'NotAllowedError'
        ? 'Camera permission denied. Paste the descriptor manually.'
        : 'Could not open camera: ' + (e?.message || e);
    return;
  }
  els.scanVideo.srcObject = scanStream;
  await els.scanVideo.play();
  els.scanStatus.textContent = 'Scanning… point at a QR code.';
  scanCanvas = scanCanvas || document.createElement('canvas');
  tick();
}

function tick() {
  const v = els.scanVideo;
  if (!v.videoWidth) {
    scanRafId = requestAnimationFrame(tick);
    return;
  }
  scanCanvas.width = v.videoWidth;
  scanCanvas.height = v.videoHeight;
  const ctx = scanCanvas.getContext('2d', { willReadFrequently: true });
  ctx.drawImage(v, 0, 0, scanCanvas.width, scanCanvas.height);
  const img = ctx.getImageData(0, 0, scanCanvas.width, scanCanvas.height);
  const result = jsQR(img.data, img.width, img.height, { inversionAttempts: 'attemptBoth' });
  if (result?.data) {
    onScanDecoded(result.data);
    return;
  }
  scanRafId = requestAnimationFrame(tick);
}

function onScanDecoded(text) {
  closeScan();
  // Coldcard's "Key Expression" QR is the BIP-380 inner expression:
  // [xfp/path]xpub  (no script-type wrapper, no /chain/index suffix).
  // Auto-wrap bare key expressions in wpkh(...) as the most common case;
  // leave anything that already looks like a full descriptor untouched.
  let value = text.trim();
  if (/^\[[0-9a-fA-F]{8}/.test(value) && /xpub|tpub|ypub|upub|zpub|vpub/.test(value)) {
    value = `wpkh(${value})`;
  }
  els.descriptor.value = value;
  els.descriptor.focus();
}

function closeScan() {
  if (scanRafId !== null) cancelAnimationFrame(scanRafId);
  scanRafId = null;
  if (scanStream) {
    for (const t of scanStream.getTracks()) t.stop();
    scanStream = null;
  }
  els.scanVideo.srcObject = null;
  els.scanModal.hidden = true;
}

els.scan.addEventListener('click', openScan);
els.scanClose.addEventListener('click', closeScan);
els.scanModal.addEventListener('click', (e) => {
  if (e.target === els.scanModal) closeScan();
});
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && !els.scanModal.hidden) closeScan();
});

els.build.addEventListener('click', () => build(true));
els.example.addEventListener('click', loadExample);
els.copy.addEventListener('click', copy);
els.download.addEventListener('click', download);
els.toggleQr.addEventListener('click', toggleQr);

for (const t of [els.message, els.descriptor]) {
  t.addEventListener('keydown', (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
      e.preventDefault();
      build();
    }
  });
  t.addEventListener('input', invalidateOutput);
}
