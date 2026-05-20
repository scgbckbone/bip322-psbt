import { hash160, concat, varBytes } from './util.js';
import { sha256 } from '@noble/hashes/sha2';
import * as secp from '@noble/secp256k1';

// --- Single-sig scriptPubKey builders ---

export function spkP2PKH(pubkey) {
  return concat(new Uint8Array([0x76, 0xa9, 0x14]), hash160(pubkey), new Uint8Array([0x88, 0xac]));
}

export function spkP2WPKH(pubkey) {
  return concat(new Uint8Array([0x00, 0x14]), hash160(pubkey));
}

export function redeemShWpkh(pubkey) {
  return spkP2WPKH(pubkey);
}

export function spkShWpkh(pubkey) {
  const redeem = redeemShWpkh(pubkey);
  return concat(new Uint8Array([0xa9, 0x14]), hash160(redeem), new Uint8Array([0x87]));
}

export function spkP2TR(pubkey33) {
  const xonly = pubkey33.slice(1);
  return concat(new Uint8Array([0x51, 0x20]), tapTweak(xonly));
}

// --- Taproot tweak (BIP-86 key-path, empty Merkle root) ---

export function tapTweak(xonlyPubkey) {
  if (xonlyPubkey.length !== 32) throw new Error('tapTweak: expected 32-byte x-only pubkey');
  const t = taggedHash('TapTweak', xonlyPubkey);
  const tn = bytesToBigInt(t) % secp.CURVE.n;
  const P = secp.ProjectivePoint.fromHex(
    '02' + Array.from(xonlyPubkey, (b) => b.toString(16).padStart(2, '0')).join(''),
  );
  const Q = P.add(secp.ProjectivePoint.BASE.multiply(tn));
  if (Q.equals(secp.ProjectivePoint.ZERO)) throw new Error('tapTweak: identity');
  return Q.toRawBytes(true).slice(1);
}

function bytesToBigInt(b) {
  let v = 0n;
  for (const byte of b) v = (v << 8n) | BigInt(byte);
  return v;
}

export function taggedHash(tag, msg) {
  const tagHash = sha256(new TextEncoder().encode(tag));
  return sha256(concat(tagHash, tagHash, msg));
}

// --- Multisig redeem script ---
//
// OP_M <push pubkey1> ... <push pubkeyN> OP_N OP_CHECKMULTISIG
//
// For BIP-67 (sortedmulti), callers are expected to pass pubkeys already
// sorted ascending bytewise.
export function multisigRedeem(m, pubkeys) {
  if (m < 1 || m > 16) throw new Error('multisig: M must be 1..16');
  if (pubkeys.length < 1 || pubkeys.length > 16) {
    throw new Error('multisig: N must be 1..16');
  }
  if (m > pubkeys.length) throw new Error('multisig: M > N');
  const op_m = new Uint8Array([0x50 + m]);
  const op_n = new Uint8Array([0x50 + pubkeys.length]);
  const pushes = pubkeys.map((pk) => varBytes(pk));
  return concat(op_m, ...pushes, op_n, new Uint8Array([0xae]));
}

// --- Multisig scriptPubKey builders ---

export function spkP2SH(redeemScript) {
  return concat(new Uint8Array([0xa9, 0x14]), hash160(redeemScript), new Uint8Array([0x87]));
}

export function spkP2WSH(witnessScript) {
  return concat(new Uint8Array([0x00, 0x20]), sha256(witnessScript));
}

// sh(wsh(...)): redeem = OP_0 PUSH32 sha256(witnessScript); spk = P2SH(redeem)
export function redeemShWsh(witnessScript) {
  return concat(new Uint8Array([0x00, 0x20]), sha256(witnessScript));
}

export function spkShWsh(witnessScript) {
  return spkP2SH(redeemShWsh(witnessScript));
}

// --- Dispatch by type ---

export function buildScripts(parsed) {
  const t = parsed.type;
  if (t === 'pkh') {
    return { spk: spkP2PKH(parsed.keys[0].pubkey) };
  }
  if (t === 'wpkh') {
    return { spk: spkP2WPKH(parsed.keys[0].pubkey) };
  }
  if (t === 'sh-wpkh') {
    return {
      spk: spkShWpkh(parsed.keys[0].pubkey),
      redeemScript: redeemShWpkh(parsed.keys[0].pubkey),
    };
  }
  if (t === 'tr') {
    return { spk: spkP2TR(parsed.keys[0].pubkey) };
  }
  if (t === 'sh-multi' || t === 'wsh-multi' || t === 'sh-wsh-multi') {
    const pubkeys = parsed.keys.map((k) => k.pubkey);
    const witnessOrRedeem = multisigRedeem(parsed.m, pubkeys);
    if (t === 'sh-multi') {
      return { spk: spkP2SH(witnessOrRedeem), redeemScript: witnessOrRedeem };
    }
    if (t === 'wsh-multi') {
      return { spk: spkP2WSH(witnessOrRedeem), witnessScript: witnessOrRedeem };
    }
    // sh-wsh-multi
    return {
      spk: spkShWsh(witnessOrRedeem),
      witnessScript: witnessOrRedeem,
      redeemScript: redeemShWsh(witnessOrRedeem),
    };
  }
  throw new Error(`unknown type: ${t}`);
}
