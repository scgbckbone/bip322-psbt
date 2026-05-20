import { bech32, bech32m, base58check } from '@scure/base';
import { sha256 } from '@noble/hashes/sha2';
import { concat } from './util.js';

const b58c = base58check(sha256);

const HRP = { mainnet: 'bc', testnet: 'tb' };
const P2PKH_VERSION = { mainnet: 0x00, testnet: 0x6f };
const P2SH_VERSION = { mainnet: 0x05, testnet: 0xc4 };

// Decode the scriptPubKey we built back into the user-facing address string
// so the user can eyeball that the descriptor pointed at the wallet they
// meant. Returns null for shapes we don't recognise (we never produce them).
export function spkToAddress(spk, network) {
  const hrp = HRP[network];

  // P2PKH: 0x76 0xa9 0x14 <20> 0x88 0xac
  if (
    spk.length === 25 &&
    spk[0] === 0x76 &&
    spk[1] === 0xa9 &&
    spk[2] === 0x14 &&
    spk[23] === 0x88 &&
    spk[24] === 0xac
  ) {
    return b58c.encode(concat(new Uint8Array([P2PKH_VERSION[network]]), spk.slice(3, 23)));
  }
  // P2SH: 0xa9 0x14 <20> 0x87
  if (spk.length === 23 && spk[0] === 0xa9 && spk[1] === 0x14 && spk[22] === 0x87) {
    return b58c.encode(concat(new Uint8Array([P2SH_VERSION[network]]), spk.slice(2, 22)));
  }
  // P2WPKH: 0x00 0x14 <20>
  if (spk.length === 22 && spk[0] === 0x00 && spk[1] === 0x14) {
    return bech32.encode(hrp, [0, ...bech32.toWords(spk.slice(2))]);
  }
  // P2WSH: 0x00 0x20 <32>
  if (spk.length === 34 && spk[0] === 0x00 && spk[1] === 0x20) {
    return bech32.encode(hrp, [0, ...bech32.toWords(spk.slice(2))]);
  }
  // P2TR: 0x51 0x20 <32>
  if (spk.length === 34 && spk[0] === 0x51 && spk[1] === 0x20) {
    return bech32m.encode(hrp, [1, ...bech32m.toWords(spk.slice(2))]);
  }
  return null;
}
