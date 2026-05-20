import { concat, i32le, u32le, u64le, varBytes, varint, hash256 } from './util.js';

// Minimal Bitcoin transaction serializer. Always serialized without the
// segwit marker/flag: BIP-322's to_spend/to_sign carry no witness data, so
// the segwit-extended form would be byte-identical to the legacy form
// anyway, and omitting the 0x00 marker keeps txid hashing simple.

export function txIn(prevTxid32, prevVout, scriptSig, nSequence) {
  // prevTxid32 is internal byte order (the .sha256/.hash field is stored as int but
  // serialized via ser_uint256 which is little-endian). We pass already-LE bytes here.
  return concat(prevTxid32, u32le(prevVout), varBytes(scriptSig), u32le(nSequence));
}

export function txOut(valueSats, scriptPubKey) {
  return concat(u64le(valueSats), varBytes(scriptPubKey));
}

export function serializeTx({ nVersion, vin, vout, nLockTime }) {
  return concat(
    i32le(nVersion),
    varint(vin.length),
    ...vin,
    varint(vout.length),
    ...vout,
    u32le(nLockTime),
  );
}

export function txid(serializedTx) {
  // Returns 32-byte txid in internal (little-endian) byte order — matches what
  // ser_uint256(self.sha256) produces in the Python reference.
  return hash256(serializedTx);
}
