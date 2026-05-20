import { concat, varint, varBytes } from './util.js';

// Match BIP-174 + the Coinkite testing PSBT serializer
// (afirmware/testing/psbt.py: BasicPSBT.serialize and PSBTSection.serialize).

const PSBT_MAGIC = new Uint8Array([0x70, 0x73, 0x62, 0x74, 0xff]); // "psbt\xff"

// Globals
const PSBT_GLOBAL_UNSIGNED_TX = 0x00;
const PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE = 0x09;

// Inputs
const PSBT_IN_NON_WITNESS_UTXO = 0x00;
const PSBT_IN_REDEEM_SCRIPT = 0x04;
const PSBT_IN_BIP32_DERIVATION = 0x06;
const PSBT_IN_TAP_BIP32_DERIVATION = 0x16;

function kv(ktype, value, key = new Uint8Array(0)) {
  const ktypeAndKey = concat(new Uint8Array([ktype]), key);
  return concat(varint(ktypeAndKey.length), ktypeAndKey, varint(value.length), value);
}

// Build a PSBT v0 for BIP-322:
//   global:
//     PSBT_GLOBAL_UNSIGNED_TX = unsignedTx
//     PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE = bip322Msg
//   input[0]:
//     PSBT_IN_NON_WITNESS_UTXO = toSpendSerialized
//     (sh-wpkh only) PSBT_IN_REDEEM_SCRIPT
//     (non-taproot) PSBT_IN_BIP32_DERIVATION  key=pubkey33  val=fp||path
//     (taproot) PSBT_IN_TAP_BIP32_DERIVATION  key=xonlyPubkey  val=0x00||fp||path
//   output[0]: empty
export function buildBip322Psbt({
  type,
  unsignedTx,
  toSpendSerialized,
  bip322Msg,
  fingerprint,
  encodedPath,
  pubkey,
  redeemScript = null,
}) {
  const globals = concat(
    kv(PSBT_GLOBAL_UNSIGNED_TX, unsignedTx),
    kv(PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE, bip322Msg),
    new Uint8Array([0x00]), // separator
  );

  const inputParts = [];
  inputParts.push(kv(PSBT_IN_NON_WITNESS_UTXO, toSpendSerialized));
  if (redeemScript) inputParts.push(kv(PSBT_IN_REDEEM_SCRIPT, redeemScript));

  if (type === 'tr') {
    // value = 0x00 (empty leaf-hash list as varint) || fingerprint || path
    const tapVal = concat(new Uint8Array([0x00]), fingerprint, encodedPath);
    const xonly = pubkey.slice(1);
    inputParts.push(kv(PSBT_IN_TAP_BIP32_DERIVATION, tapVal, xonly));
  } else {
    const val = concat(fingerprint, encodedPath);
    inputParts.push(kv(PSBT_IN_BIP32_DERIVATION, val, pubkey));
  }
  inputParts.push(new Uint8Array([0x00])); // input separator
  const input0 = concat(...inputParts);

  const output0 = new Uint8Array([0x00]); // empty output map: just separator

  return concat(PSBT_MAGIC, globals, input0, output0);
}
