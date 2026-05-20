import { concat, varint } from './util.js';

// Matches the Coinkite test PSBT serializer (afirmware/testing/psbt.py):
// global UNSIGNED_TX and GENERIC_SIGNED_MESSAGE, separator, one input, one
// output. The input field order in psbt.py serialize_kvs is:
//   utxo, witness_utxo, redeem_script, witness_script, ...,
//   bip32_paths, taproot_bip32_paths, ...

const PSBT_MAGIC = new Uint8Array([0x70, 0x73, 0x62, 0x74, 0xff]);

const PSBT_GLOBAL_UNSIGNED_TX = 0x00;
const PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE = 0x09;

const PSBT_IN_NON_WITNESS_UTXO = 0x00;
const PSBT_IN_REDEEM_SCRIPT = 0x04;
const PSBT_IN_WITNESS_SCRIPT = 0x05;
const PSBT_IN_BIP32_DERIVATION = 0x06;
const PSBT_IN_TAP_BIP32_DERIVATION = 0x16;

function kv(ktype, value, key = new Uint8Array(0)) {
  const ktypeAndKey = concat(new Uint8Array([ktype]), key);
  return concat(varint(ktypeAndKey.length), ktypeAndKey, varint(value.length), value);
}

// Build a single-input BIP-322 PSBT v0.
// Args:
//   type:               descriptor type, used to choose tap vs regular bip32 derivation
//   unsignedTx:         serialized to_sign
//   toSpendSerialized:  serialized to_spend (goes into NON_WITNESS_UTXO)
//   bip322Msg:          message bytes for PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE
//   redeemScript:       optional bytes
//   witnessScript:      optional bytes
//   keys:               [{ fingerprint, encodedPath, pubkey }, ...] — emitted in array
//                       order (caller pre-sorts for sortedmulti / BIP-67)
export function buildBip322Psbt({
  type,
  unsignedTx,
  toSpendSerialized,
  bip322Msg,
  redeemScript = null,
  witnessScript = null,
  keys,
}) {
  const globals = concat(
    kv(PSBT_GLOBAL_UNSIGNED_TX, unsignedTx),
    kv(PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE, bip322Msg),
    new Uint8Array([0x00]),
  );

  const inputParts = [];
  inputParts.push(kv(PSBT_IN_NON_WITNESS_UTXO, toSpendSerialized));
  if (redeemScript) inputParts.push(kv(PSBT_IN_REDEEM_SCRIPT, redeemScript));
  if (witnessScript) inputParts.push(kv(PSBT_IN_WITNESS_SCRIPT, witnessScript));

  if (type === 'tr') {
    // Single key only — value = 0x00 (empty leaf-hash list varint) || fp || path
    const k = keys[0];
    const tapVal = concat(new Uint8Array([0x00]), k.fingerprint, k.encodedPath);
    inputParts.push(kv(PSBT_IN_TAP_BIP32_DERIVATION, tapVal, k.pubkey.slice(1)));
  } else {
    for (const k of keys) {
      const val = concat(k.fingerprint, k.encodedPath);
      inputParts.push(kv(PSBT_IN_BIP32_DERIVATION, val, k.pubkey));
    }
  }

  inputParts.push(new Uint8Array([0x00]));
  const input0 = concat(...inputParts);
  const output0 = new Uint8Array([0x00]);

  return concat(PSBT_MAGIC, globals, input0, output0);
}
