import { base58check } from '@scure/base';
import { sha256 } from '@noble/hashes/sha2';
import { hmac } from '@noble/hashes/hmac';
import { sha512 } from '@noble/hashes/sha2';
import * as secp from '@noble/secp256k1';
import { concat, hex } from './util.js';

const b58c = base58check(sha256);

const VERSIONS = {
  mainnet: { xpub: 0x0488b21e, xprv: 0x0488ade4 },
  testnet: { xpub: 0x043587cf, xprv: 0x04358394 },
};

const HARDENED = 0x80000000;

export function decodeXpub(s) {
  const raw = b58c.decode(s);
  if (raw.length !== 78) throw new Error(`xpub: bad length ${raw.length}`);
  const dv = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
  const version = dv.getUint32(0, false);
  let network = null;
  for (const [name, v] of Object.entries(VERSIONS)) {
    if (v.xpub === version) network = name;
  }
  if (!network) throw new Error(`xpub: unrecognized version 0x${version.toString(16)}`);
  const depth = raw[4];
  const parentFp = raw.slice(5, 9);
  const childNum = dv.getUint32(9, false);
  const chainCode = raw.slice(13, 45);
  const pubkey = raw.slice(45, 78);
  if (pubkey[0] !== 0x02 && pubkey[0] !== 0x03) {
    throw new Error('xpub: not a public key (does it start with 02/03?)');
  }
  return { network, depth, parentFp, childNum, chainCode, pubkey };
}

// Derive a non-hardened child from (parent_pubkey, parent_chain_code).
// Returns { pubkey: Uint8Array(33), chainCode: Uint8Array(32) }.
export function ckdPub(parentPubkey, parentChainCode, index) {
  if (index < 0 || index >= HARDENED) {
    throw new Error('hardened derivation from xpub is impossible');
  }
  const idxBE = new Uint8Array(4);
  new DataView(idxBE.buffer).setUint32(0, index, false);
  const I = hmac(sha512, parentChainCode, concat(parentPubkey, idxBE));
  const IL = I.slice(0, 32);
  const IR = I.slice(32, 64);

  const il = bytesToBigInt(IL);
  if (il === 0n || il >= secp.CURVE.n) {
    throw new Error('IL out of range; pick next index');
  }
  const parentPoint = secp.ProjectivePoint.fromHex(hex(parentPubkey));
  const childPoint = parentPoint.add(secp.ProjectivePoint.BASE.multiply(il));
  if (childPoint.equals(secp.ProjectivePoint.ZERO)) {
    throw new Error('child point is identity; pick next index');
  }
  const childPub = childPoint.toRawBytes(true);
  return { pubkey: childPub, chainCode: IR };
}

export function derivePath(xpub, steps) {
  let { pubkey, chainCode } = xpub;
  for (const step of steps) {
    if (step >= HARDENED) {
      throw new Error(
        `Hardened step h${step & 0x7fffffff} after the xpub is impossible — derive a deeper account xpub and use only non-hardened steps in the descriptor's child path.`,
      );
    }
    ({ pubkey, chainCode } = ckdPub(pubkey, chainCode, step));
  }
  return { pubkey, chainCode };
}

function bytesToBigInt(b) {
  let v = 0n;
  for (const byte of b) v = (v << 8n) | BigInt(byte);
  return v;
}

export function encodePath(steps) {
  // each step as 4 bytes little-endian
  const out = new Uint8Array(steps.length * 4);
  const dv = new DataView(out.buffer);
  for (let i = 0; i < steps.length; i++) dv.setUint32(i * 4, steps[i] >>> 0, true);
  return out;
}

export function parseStep(s) {
  if (!s.length) throw new Error('empty path step');
  const hardened = s.endsWith("'") || s.endsWith('h') || s.endsWith('H');
  const numStr = hardened ? s.slice(0, -1) : s;
  const n = Number(numStr);
  if (!Number.isInteger(n) || n < 0 || n >= HARDENED) throw new Error(`bad path step: ${s}`);
  return hardened ? (n | 0) | HARDENED : n;
}

export function parsePath(s) {
  // Accepts "m/84h/0h/0h" or "84h/0h/0h" or "0/0".
  const parts = s.split('/').filter((p) => p.length > 0 && p !== 'm');
  return parts.map(parseStep);
}
