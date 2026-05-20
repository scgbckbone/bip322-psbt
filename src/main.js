import { buildBip322Bundle } from './bip322.js';

const $ = (id) => document.getElementById(id);

const els = {
  message: $('message'),
  descriptor: $('descriptor'),
  build: $('build'),
  copy: $('copy'),
  psbt: $('psbt'),
  network: $('network'),
  type: $('type'),
  output: $('output'),
  status: $('status'),
  error: $('error'),
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
    els.output.hidden = false;
    els.status.textContent = '';
  } catch (e) {
    showError(e.message || String(e));
  }
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
els.copy.addEventListener('click', copy);

// Submit on Cmd/Ctrl+Enter from either textarea.
for (const t of [els.message, els.descriptor]) {
  t.addEventListener('keydown', (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
      e.preventDefault();
      build();
    }
  });
}
