import { decodeXpub, derivePath, parsePath } from './bip32.js';
import { fromHex } from './util.js';

const TYPES = new Set(['pkh', 'wpkh', 'sh-wpkh', 'tr']);

// Parses a single-sig descriptor:
//   pkh([fp/path]xpub.../i/j)
//   wpkh([fp/path]xpub.../i/j)
//   sh(wpkh([fp/path]xpub.../i/j))
//   tr([fp/path]xpub.../i/j)
//
// The xpub-internal path (everything after the xpub) must be non-hardened
// and have no wildcards. An optional #checksum suffix is accepted but
// not validated.
export function parseDescriptor(input) {
  let s = String(input).trim();
  if (!s) throw new Error('Descriptor is empty.');

  // Strip optional checksum.
  const hashIdx = s.indexOf('#');
  if (hashIdx !== -1) s = s.slice(0, hashIdx);

  if (!s.endsWith(')')) throw new Error('Descriptor must end with ")".');

  let type;
  let inner;
  if (s.startsWith('sh(wpkh(')) {
    if (!s.endsWith('))')) throw new Error('sh(wpkh(...)) missing closing parens.');
    type = 'sh-wpkh';
    inner = s.slice('sh(wpkh('.length, -2);
  } else if (s.startsWith('wpkh(')) {
    type = 'wpkh';
    inner = s.slice('wpkh('.length, -1);
  } else if (s.startsWith('pkh(')) {
    type = 'pkh';
    inner = s.slice('pkh('.length, -1);
  } else if (s.startsWith('tr(')) {
    type = 'tr';
    inner = s.slice('tr('.length, -1);
    // No script tree support in v1.
    if (inner.includes(',')) {
      throw new Error('tr() with a script tree is not supported (key-path only).');
    }
  } else {
    throw new Error('Unsupported descriptor type. Use pkh / wpkh / sh(wpkh(...)) / tr.');
  }

  const key = parseKeyExpression(inner);
  if (!TYPES.has(type)) throw new Error(`Unsupported type: ${type}`);

  const { pubkey } = derivePath(key.xpub, key.childSteps);
  const fullPath = [...key.originSteps, ...key.childSteps];

  return {
    type,
    network: key.xpub.network,
    fingerprint: key.fingerprint, // 4 bytes
    path: fullPath, // full path from master, as numbers (hardened encoded with 0x80000000)
    pubkey, // 33-byte compressed
  };
}

function parseKeyExpression(expr) {
  let s = expr.trim();
  if (!s.startsWith('[')) {
    throw new Error('Key expression must start with origin info, e.g. [fp/84h/0h/0h]xpub.../0/0');
  }
  const end = s.indexOf(']');
  if (end === -1) throw new Error('Missing "]" in origin info.');

  const origin = s.slice(1, end);
  const rest = s.slice(end + 1);

  const originParts = origin.split('/');
  if (originParts.length < 1) throw new Error('Empty origin info.');
  const fpHex = originParts[0];
  if (!/^[0-9a-fA-F]{8}$/.test(fpHex)) {
    throw new Error('Origin fingerprint must be 8 hex chars (4 bytes).');
  }
  const fingerprint = fromHex(fpHex);
  const originPathStr = originParts.slice(1).join('/');
  const originSteps = originPathStr ? parsePath(originPathStr) : [];

  // rest is xpub then optional /i/j... (non-hardened, no wildcards)
  let xpubStr;
  let childPathStr = '';
  const slash = rest.indexOf('/');
  if (slash === -1) {
    xpubStr = rest;
  } else {
    xpubStr = rest.slice(0, slash);
    childPathStr = rest.slice(slash + 1);
  }
  if (!xpubStr) throw new Error('Missing xpub in key expression.');

  if (childPathStr.includes('*')) {
    throw new Error('Wildcard (*) child paths are not supported. Use a concrete child like /0/0.');
  }
  const childSteps = childPathStr ? parsePath(childPathStr) : [];
  for (const step of childSteps) {
    if (step >= 0x80000000) {
      throw new Error(
        'Hardened steps after the xpub are not derivable. Move them inside the [origin] section.',
      );
    }
  }

  const xpub = decodeXpub(xpubStr);
  return { fingerprint, originSteps, xpub, childSteps };
}
