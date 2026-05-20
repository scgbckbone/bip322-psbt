import { parseDescriptor } from './descriptor.js';
import { buildScripts, taggedHash } from './scripts.js';
import { encodePath } from './bip32.js';
import { serializeTx, txIn, txOut, txid } from './tx.js';
import { buildBip322Psbt } from './psbt.js';
import { concat, utf8, bytesToBase64 } from './util.js';

const ZERO_TXID = new Uint8Array(32);

export function bip322MsgHash(msgBytes) {
  return taggedHash('BIP0322-signed-message', msgBytes);
}

// Build the BIP-322 PSBT for a descriptor + message. Returns the raw PSBT
// bytes, the base64 form, the script we built (for address display), and
// metadata about the parsed descriptor.
//
// Byte-equality with the fixtures in test/ is asserted by the Vitest suite;
// those fixtures are produced by scripts/gen_*.py using an independent
// Python BIP-322 implementation.
export function buildBip322Bundle({ message, descriptor }) {
  const parsed = parseDescriptor(descriptor);
  const msgBytes = typeof message === 'string' ? utf8(message) : message;

  const { spk, redeemScript = null, witnessScript = null } = buildScripts(parsed);
  const msgHash = bip322MsgHash(msgBytes);

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

  const toSignVin = txIn(toSpendTxid, 0, new Uint8Array(0), 0xffffffff);
  const toSignVout = txOut(0n, new Uint8Array([0x6a]));
  const unsignedTx = serializeTx({
    nVersion: 0,
    vin: [toSignVin],
    vout: [toSignVout],
    nLockTime: 0,
  });

  const psbtKeys = parsed.keys.map((k) => ({
    fingerprint: k.fingerprint,
    encodedPath: encodePath(k.path),
    pubkey: k.pubkey,
  }));

  const psbt = buildBip322Psbt({
    type: parsed.type,
    unsignedTx,
    toSpendSerialized,
    bip322Msg: msgBytes,
    redeemScript,
    witnessScript,
    keys: psbtKeys,
  });

  return {
    psbtBytes: psbt,
    psbtBase64: bytesToBase64(psbt),
    network: parsed.network,
    type: parsed.type,
    scriptPubKey: spk,
    msgHash,
    m: parsed.m,
    n: parsed.n,
    sorted: parsed.sorted,
  };
}
