import { hash160, concat } from './util.js';
import { sha256 } from '@noble/hashes/sha2';
import * as secp from '@noble/secp256k1';

// scriptPubKey builders by type. Inputs:
//   pubkey: 33-byte compressed.

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

// BIP-341 / BIP-86 key-path-only taproot tweak with empty Merkle root.
//   t = tagged_hash("TapTweak", x_only(P))
//   Q = P + t*G
//   spk = OP_1 <x_only(Q)>
export function spkP2TR(pubkey33) {
  const xonly = pubkey33.slice(1);
  return concat(new Uint8Array([0x51, 0x20]), tapTweak(xonly));
}

export function tapTweak(xonlyPubkey) {
  if (xonlyPubkey.length !== 32) throw new Error('tapTweak: expected 32-byte x-only pubkey');
  const t = taggedHash('TapTweak', xonlyPubkey);
  const tn = bytesToBigInt(t) % secp.CURVE.n;
  // Lift xonly to a point with even Y (the BIP-340 convention).
  const P = secp.ProjectivePoint.fromHex('02' + Array.from(xonlyPubkey, (b) => b.toString(16).padStart(2, '0')).join(''));
  const Q = P.add(secp.ProjectivePoint.BASE.multiply(tn));
  if (Q.equals(secp.ProjectivePoint.ZERO)) throw new Error('tapTweak: identity');
  return Q.toRawBytes(true).slice(1); // x-only
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

export function spkFor(type, pubkey) {
  switch (type) {
    case 'pkh':
      return spkP2PKH(pubkey);
    case 'wpkh':
      return spkP2WPKH(pubkey);
    case 'sh-wpkh':
      return spkShWpkh(pubkey);
    case 'tr':
      return spkP2TR(pubkey);
    default:
      throw new Error(`unknown type: ${type}`);
  }
}
