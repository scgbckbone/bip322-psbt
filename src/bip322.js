import { parseDescriptor } from './descriptor.js';
import { spkFor, redeemShWpkh, taggedHash } from './scripts.js';
import { encodePath } from './bip32.js';
import { serializeTx, txIn, txOut, txid } from './tx.js';
import { buildBip322Psbt } from './psbt.js';
import { concat, utf8, bytesToBase64 } from './util.js';

const ZERO_TXID = new Uint8Array(32);

export function bip322MsgHash(msgBytes) {
  return taggedHash('BIP0322-signed-message', msgBytes);
}

// Build the BIP-322 "simple"/"full" PSBT for a single-input single-sig descriptor.
// Matches afirmware/testing/bip322.py byte-for-byte.
export function buildBip322Bundle({ message, descriptor }) {
  const parsed = parseDescriptor(descriptor);
  const msgBytes = typeof message === 'string' ? utf8(message) : message;

  const spk = spkFor(parsed.type, parsed.pubkey);
  const msgHash = bip322MsgHash(msgBytes);

  // to_spend: nVersion=0, nLockTime=0
  //   vin[0]: prev_txid=0x00*32, prev_vout=0xffffffff, scriptSig=OP_0 PUSH32(msgHash), nSequence=0
  //   vout[0]: value=0, scriptPubKey=spk
  const toSpendVin = txIn(
    ZERO_TXID,
    0xffffffff,
    concat(new Uint8Array([0x00, 0x20]), msgHash),
    0,
  );
  const toSpendVout = txOut(0n, spk);
  const toSpendSerialized = serializeTx({
    nVersion: 0,
    vin: [toSpendVin],
    vout: [toSpendVout],
    nLockTime: 0,
  });
  const toSpendTxid = txid(toSpendSerialized);

  // to_sign: nVersion=0, nLockTime=0
  //   vin[0]: prev = toSpendTxid:0, nSequence=0xffffffff
  //   vout[0]: value=0, scriptPubKey=OP_RETURN (0x6a)
  const toSignVin = txIn(toSpendTxid, 0, new Uint8Array(0), 0xffffffff);
  const toSignVout = txOut(0n, new Uint8Array([0x6a]));
  const unsignedTx = serializeTx({
    nVersion: 0,
    vin: [toSignVin],
    vout: [toSignVout],
    nLockTime: 0,
  });

  const encodedPath = encodePath(parsed.path);
  const psbt = buildBip322Psbt({
    type: parsed.type,
    unsignedTx,
    toSpendSerialized,
    bip322Msg: msgBytes,
    fingerprint: parsed.fingerprint,
    encodedPath,
    pubkey: parsed.pubkey,
    redeemScript: parsed.type === 'sh-wpkh' ? redeemShWpkh(parsed.pubkey) : null,
  });

  return {
    psbtBytes: psbt,
    psbtBase64: bytesToBase64(psbt),
    network: parsed.network,
    type: parsed.type,
    scriptPubKey: spk,
    msgHash,
  };
}
