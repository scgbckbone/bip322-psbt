import { decodeXpub, derivePath, parsePath } from './bip32.js';
import { fromHex } from './util.js';

// Returned shape:
//   {
//     type: 'pkh' | 'wpkh' | 'sh-wpkh' | 'tr'
//         | 'sh-multi' | 'wsh-multi' | 'sh-wsh-multi',
//     network: 'mainnet' | 'testnet',
//     keys: [{ fingerprint: Uint8Array(4), path: number[], pubkey: Uint8Array(33) }, ...],
//     // multisig-only:
//     m, n, sorted
//   }
//
// Single-sig descriptors return keys of length 1 and no m/n/sorted.
// Multisig keys are returned in the order the PSBT must encode them — i.e.
// pubkey-sorted (BIP-67) for sortedmulti, descriptor order for multi.

export function parseDescriptor(input) {
  let s = String(input).trim();
  if (!s) throw new Error('Descriptor is empty.');

  // Strip optional checksum.
  const hashIdx = s.indexOf('#');
  if (hashIdx !== -1) s = s.slice(0, hashIdx);

  if (!s.endsWith(')')) throw new Error('Descriptor must end with ")".');

  // sh(wsh(multi/sortedmulti(...)))
  if (s.startsWith('sh(wsh(') && s.endsWith(')))')) {
    const inner = s.slice('sh(wsh('.length, -3);
    const m = parseMultiInner(inner);
    return finishMulti('sh-wsh-multi', m);
  }
  // sh(wpkh(KEY))
  if (s.startsWith('sh(wpkh(') && s.endsWith('))')) {
    const inner = s.slice('sh(wpkh('.length, -2);
    return finishSingle('sh-wpkh', parseKeyExpression(inner));
  }
  // wsh(multi/sortedmulti(...))
  if (s.startsWith('wsh(') && s.endsWith(')')) {
    const inner = s.slice('wsh('.length, -1);
    const m = parseMultiInner(inner);
    return finishMulti('wsh-multi', m);
  }
  // sh(multi/sortedmulti(...))
  if (s.startsWith('sh(') && s.endsWith(')')) {
    const inner = s.slice('sh('.length, -1);
    const m = parseMultiInner(inner);
    return finishMulti('sh-multi', m);
  }
  // wpkh(KEY)
  if (s.startsWith('wpkh(') && s.endsWith(')')) {
    return finishSingle('wpkh', parseKeyExpression(s.slice('wpkh('.length, -1)));
  }
  // pkh(KEY)
  if (s.startsWith('pkh(') && s.endsWith(')')) {
    return finishSingle('pkh', parseKeyExpression(s.slice('pkh('.length, -1)));
  }
  // tr(KEY)
  if (s.startsWith('tr(') && s.endsWith(')')) {
    const inner = s.slice('tr('.length, -1);
    if (inner.startsWith('multi_a(') || inner.startsWith('sortedmulti_a(')) {
      throw new Error('Taproot multisig (multi_a / sortedmulti_a) is not supported.');
    }
    if (inner.includes(',')) {
      throw new Error('tr() with a script tree is not supported (key-path only).');
    }
    return finishSingle('tr', parseKeyExpression(inner));
  }

  throw new Error(
    'Unsupported descriptor type. Use pkh/wpkh/sh(wpkh)/tr or sh/wsh/sh(wsh) wrapping multi/sortedmulti.',
  );
}

function finishSingle(type, key) {
  return {
    type,
    network: key.xpub.network,
    keys: [
      {
        fingerprint: key.fingerprint,
        path: [...key.originSteps, ...key.childSteps],
        pubkey: derivePath(key.xpub, key.childSteps).pubkey,
      },
    ],
  };
}

function finishMulti(type, m) {
  // Derive each cosigner pubkey, then sort by pubkey if sortedmulti.
  const derived = m.keys.map((k) => ({
    fingerprint: k.fingerprint,
    path: [...k.originSteps, ...k.childSteps],
    pubkey: derivePath(k.xpub, k.childSteps).pubkey,
    network: k.xpub.network,
  }));

  // All keys must share a network (mixing main+test in one descriptor would
  // produce a meaningless address).
  const networks = new Set(derived.map((d) => d.network));
  if (networks.size !== 1) {
    throw new Error('Multisig descriptor mixes mainnet and testnet keys.');
  }

  if (m.sorted) {
    derived.sort((a, b) => bytewiseCompare(a.pubkey, b.pubkey));
  }

  return {
    type,
    network: [...networks][0],
    m: m.m,
    n: derived.length,
    sorted: m.sorted,
    keys: derived.map(({ network, ...k }) => k),
  };
}

function parseMultiInner(inner) {
  let sorted;
  let body;
  if (inner.startsWith('sortedmulti(') && inner.endsWith(')')) {
    sorted = true;
    body = inner.slice('sortedmulti('.length, -1);
  } else if (inner.startsWith('multi(') && inner.endsWith(')')) {
    sorted = false;
    body = inner.slice('multi('.length, -1);
  } else {
    throw new Error('sh()/wsh()/sh(wsh()) must wrap multi(...) or sortedmulti(...).');
  }

  const parts = body.split(',');
  if (parts.length < 2) throw new Error('multi(M,...) needs at least one key after M.');

  const m = Number(parts[0]);
  if (!Number.isInteger(m) || m < 1 || m > 16) {
    throw new Error(`multi(M, ...): M must be an integer 1..16 (got "${parts[0]}").`);
  }
  const keyParts = parts.slice(1);
  if (keyParts.length > 16) {
    throw new Error('multi() supports at most 16 cosigners.');
  }
  if (m > keyParts.length) {
    throw new Error(`multi(${m},...) only has ${keyParts.length} keys (need at least M).`);
  }

  const keys = keyParts.map((p) => parseKeyExpression(p.trim()));
  return { m, sorted, keys };
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

function bytewiseCompare(a, b) {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}
