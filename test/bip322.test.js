import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { buildBip322Bundle } from '../src/bip322.js';
import { parseDescriptor } from '../src/descriptor.js';
import { fromHex, hex } from '../src/util.js';
import { bip322MsgHash } from '../src/bip322.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixtures = JSON.parse(readFileSync(join(here, 'fixtures.json'), 'utf8'));
const msFixtures = JSON.parse(readFileSync(join(here, 'ms_fixtures.json'), 'utf8'));

describe('BIP-322 PSBT — single-sig byte-for-byte vs Python reference', () => {
  for (const f of fixtures) {
    it(f.name, () => {
      const { psbtBase64, network, type } = buildBip322Bundle({
        message: fromHex(f.message_hex),
        descriptor: f.descriptor,
      });
      expect(network).toBe(f.network);
      expect(type).toBe(f.type);
      expect(psbtBase64).toBe(f.expected_psbt_base64);
    });
  }
});

describe('BIP-322 PSBT — multisig byte-for-byte vs Python reference', () => {
  for (const f of msFixtures) {
    it(f.name, () => {
      const r = buildBip322Bundle({
        message: fromHex(f.message_hex),
        descriptor: f.descriptor,
      });
      expect(r.network).toBe(f.network);
      expect(r.type).toBe(f.type);
      expect(r.m).toBe(f.m);
      expect(r.n).toBe(f.n);
      expect(r.sorted).toBe(f.sorted);
      expect(r.psbtBase64).toBe(f.expected_psbt_base64);
    });
  }
});

describe('descriptor parser', () => {
  const xpub =
    'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8';

  it('rejects empty input', () => {
    expect(() => parseDescriptor('')).toThrow();
  });

  it('accepts a descriptor with origin info omitted', () => {
    expect(() => parseDescriptor(`wpkh(${xpub}/0/0)`)).not.toThrow();
  });

  it('rejects wildcard child paths', () => {
    expect(() => parseDescriptor(`wpkh([deadbeef]${xpub}/0/*)`)).toThrow(/wildcard/i);
  });

  it('rejects hardened steps after the xpub', () => {
    expect(() => parseDescriptor(`wpkh([deadbeef]${xpub}/0h/0)`)).toThrow(/[Hh]ardened/);
  });

  it('rejects tr() with a script tree', () => {
    expect(() => parseDescriptor(`tr([deadbeef]${xpub}/0/0,foo)`)).toThrow(/script tree/i);
  });

  it('strips an optional #checksum suffix without validating', () => {
    const a = parseDescriptor(`wpkh([deadbeef]${xpub}/0/0)`);
    const b = parseDescriptor(`wpkh([deadbeef]${xpub}/0/0)#zzzzzzzz`);
    expect([...a.keys[0].pubkey]).toEqual([...b.keys[0].pubkey]);
  });

  it('exposes the full master-relative path including origin steps', () => {
    const r = parseDescriptor(`wpkh([deadbeef/84h/0h/0h]${xpub}/0/5)`);
    const HARDENED = 0x80000000;
    expect(r.keys[0].path).toEqual([84 | HARDENED, 0 | HARDENED, 0 | HARDENED, 0, 5]);
  });

  it('accepts a descriptor key without origin info', () => {
    // Per BIP-32, fingerprint = hash160(pubkey)[:4]. For a master xpub the
    // computed fp must equal what an explicit origin would carry. Use the
    // simulator xpub (master fp = 0f056943) to lock that down.
    const simXpub =
      'xpub661MyMwAqRbcGC9DmWbtbAmuUjpMYxw4BWE88NSDHB3jSjfUK7KtYJuKa52GbowD3DVLkgsxH9QwPnTx5mjdHykYFEncnmAsNsCTbWzBhA7';
    const a = buildBip322Bundle({
      message: 'POR',
      descriptor: `wpkh([0f056943]${simXpub}/0/0)`,
    });
    const b = buildBip322Bundle({
      message: 'POR',
      descriptor: `wpkh(${simXpub}/0/0)`,
    });
    expect(b.psbtBase64).toBe(a.psbtBase64);
  });

  it('accepts bare xpub with no child path (derives at xpub itself)', () => {
    const r = parseDescriptor(`wpkh(${xpub})`);
    expect(r.keys[0].path).toEqual([]);
    expect(r.keys[0].fingerprint.length).toBe(4);
  });

  it('rejects taproot multisig (multi_a)', () => {
    expect(() =>
      parseDescriptor(`tr(multi_a(2,[deadbeef]${xpub}/0/0,[deadbef1]${xpub}/0/0))`),
    ).toThrow(/Taproot multisig/);
  });

  it('rejects multi() with M > N', () => {
    expect(() =>
      parseDescriptor(`wsh(multi(3,[deadbeef]${xpub}/0/0,[deadbef1]${xpub}/0/0))`),
    ).toThrow(/M > N|need at least M/i);
  });

  it('rejects multi() with non-integer M', () => {
    expect(() =>
      parseDescriptor(`wsh(multi(x,[deadbeef]${xpub}/0/0,[deadbef1]${xpub}/0/0))`),
    ).toThrow(/M must be an integer/);
  });

  it('rejects multi descriptors mixing mainnet + testnet keys', () => {
    const tpub =
      'tpubD6NzVbkrYhZ4XzL5Dhayo67Gorv1YMS7j8pRUvVMd5odC2LBPLAygka9p7748JtSq82FNGPppFEz5xxZUdasBRCqJqXvUHq6xpnsMcYJzeh';
    expect(() =>
      parseDescriptor(`wsh(multi(2,[deadbeef]${xpub}/0/0,[deadbef1]${tpub}/0/0))`),
    ).toThrow(/mainnet and testnet/i);
  });

  it('sortedmulti() reorders keys by pubkey while multi() preserves descriptor order', () => {
    const xpub2 =
      'xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB';
    const a = parseDescriptor(`wsh(multi(1,[deadbeef]${xpub}/0/0,[deadbef1]${xpub2}/0/0))`);
    const b = parseDescriptor(`wsh(sortedmulti(1,[deadbeef]${xpub}/0/0,[deadbef1]${xpub2}/0/0))`);

    const aPub0 = a.keys[0].pubkey;
    const sortedPub0 = b.keys[0].pubkey;
    // sortedmulti must put the lexicographically-smaller pubkey first.
    expect([...sortedPub0].slice(0, 1)[0]).toBeLessThanOrEqual([...b.keys[1].pubkey][0]);

    // If the original order already happens to be sorted, the two are equal; otherwise they differ.
    const alreadySorted =
      [...a.keys[0].pubkey].slice(0, 4).every((b0, i) => b0 <= a.keys[1].pubkey[i]) ||
      [...a.keys[0].pubkey].slice(0, 4).every((b0, i) => b0 === a.keys[1].pubkey[i]);
    if (!alreadySorted) {
      expect([...aPub0]).not.toEqual([...sortedPub0]);
    }
  });
});

describe('descriptor parser — bare compressed public keys', () => {
  // Simulator xpub (master fp 0f056943). Derive concrete compressed pubkeys
  // from it so the bare-key tests use real, on-curve keys.
  const simXpub =
    'xpub661MyMwAqRbcGC9DmWbtbAmuUjpMYxw4BWE88NSDHB3jSjfUK7KtYJuKa52GbowD3DVLkgsxH9QwPnTx5mjdHykYFEncnmAsNsCTbWzBhA7';
  const xpub2 =
    'xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB';
  const pk = hex(parseDescriptor(`wpkh([0f056943]${simXpub}/0/0)`).keys[0].pubkey);
  const pk2 = hex(parseDescriptor(`wpkh([deadbef1]${xpub2}/0/0)`).keys[0].pubkey);

  it('accepts a bare compressed pubkey with origin info', () => {
    const r = parseDescriptor(`wpkh([0f056943/84h/0h/0h/0/0]${pk})`);
    const HARDENED = 0x80000000;
    expect(r.keys).toHaveLength(1);
    expect(hex(r.keys[0].pubkey)).toBe(pk);
    expect(r.keys[0].path).toEqual([84 | HARDENED, 0 | HARDENED, 0 | HARDENED, 0, 0]);
    expect([...r.keys[0].fingerprint]).toEqual([0x0f, 0x05, 0x69, 0x43]);
  });

  it('accepts a bare pubkey with origin info omitted (fp = hash160(pubkey)[:4])', () => {
    const r = parseDescriptor(`wpkh(${pk})`);
    expect(hex(r.keys[0].pubkey)).toBe(pk);
    expect(r.keys[0].path).toEqual([]);
    expect(r.keys[0].fingerprint.length).toBe(4);
  });

  it('a bare pubkey is byte-for-byte equivalent to the xpub it was derived from', () => {
    // [0f056943]xpub/0/0 stores fp=0f056943, path=[0,0], pubkey=derived.
    // [0f056943/0/0]<that pubkey> stores the identical fp, path and pubkey,
    // so the two must produce an identical PSBT.
    const fromXpub = buildBip322Bundle({
      message: 'POR',
      descriptor: `wpkh([0f056943]${simXpub}/0/0)`,
    });
    const fromBare = buildBip322Bundle({
      message: 'POR',
      descriptor: `wpkh([0f056943/0/0]${pk})`,
    });
    expect(fromBare.psbtBase64).toBe(fromXpub.psbtBase64);
  });

  it('defaults network to mainnet for a bare-pubkey descriptor', () => {
    expect(parseDescriptor(`wpkh([0f056943]${pk})`).network).toBe('mainnet');
  });

  it('accepts bare pubkeys in a multisig descriptor', () => {
    const r = parseDescriptor(`wsh(sortedmulti(1,[deadbeef]${pk},[deadbef1]${pk2}))`);
    expect(r.type).toBe('wsh-multi');
    expect(r.n).toBe(2);
    expect(r.network).toBe('mainnet');
    // sortedmulti must order cosigners by pubkey (BIP-67).
    expect(hex(r.keys[0].pubkey) < hex(r.keys[1].pubkey)).toBe(true);
  });

  it('allows mixing a bare pubkey and an xpub in multisig (network from the xpub)', () => {
    const r = parseDescriptor(`wsh(multi(1,[deadbeef]${pk},[deadbef1]${simXpub}/0/0))`);
    expect(r.network).toBe('mainnet');
    expect(r.n).toBe(2);
  });

  it('rejects a child derivation path after a bare pubkey', () => {
    expect(() => parseDescriptor(`wpkh([0f056943]${pk}/0/0)`)).toThrow(
      /bare public key cannot have a child/i,
    );
  });

  it('rejects an uncompressed public key', () => {
    const uncompressed = '04' + 'a'.repeat(128);
    expect(() => parseDescriptor(`wpkh([0f056943]${uncompressed})`)).toThrow(/uncompressed/i);
  });

  it('rejects an x-only (32-byte) public key outside tr()', () => {
    const xonly = hex(parseDescriptor(`tr([0f056943]${simXpub}/0/0)`).keys[0].pubkey).slice(2);
    for (const t of ['wpkh', 'pkh', 'sh(wpkh']) {
      const close = t === 'sh(wpkh' ? '))' : ')';
      expect(() => parseDescriptor(`${t}([0f056943]${xonly}${close}`)).toThrow(
        /x-only.*only allowed inside tr/i,
      );
    }
  });

  it('rejects an x-only key in a multisig descriptor', () => {
    const xonly = hex(parseDescriptor(`tr([0f056943]${simXpub}/0/0)`).keys[0].pubkey).slice(2);
    expect(() => parseDescriptor(`wsh(multi(1,[deadbeef]${xonly},[deadbef1]${pk2}))`)).toThrow(
      /x-only.*only allowed inside tr/i,
    );
  });
});

describe('descriptor parser — x-only public keys in tr()', () => {
  const simXpub =
    'xpub661MyMwAqRbcGC9DmWbtbAmuUjpMYxw4BWE88NSDHB3jSjfUK7KtYJuKa52GbowD3DVLkgsxH9QwPnTx5mjdHykYFEncnmAsNsCTbWzBhA7';
  // x-only key = the derived taproot key with its 1-byte parity prefix dropped.
  const compressed = hex(parseDescriptor(`tr([0f056943]${simXpub}/0/0)`).keys[0].pubkey);
  const xonly = compressed.slice(2);

  it('accepts a bare x-only key inside tr() and normalises it to 33 bytes', () => {
    const r = parseDescriptor(`tr([0f056943/0/0]${xonly})`);
    expect(r.type).toBe('tr');
    expect(r.keys[0].pubkey.length).toBe(33);
    // Normalised with an even (0x02) parity prefix; x-coordinate preserved.
    expect(hex(r.keys[0].pubkey)).toBe('02' + xonly);
    expect(r.keys[0].path).toEqual([0, 0]);
  });

  it('an x-only tr() key yields the same PSBT as the xpub it came from', () => {
    // Taproot serialises only the x-coordinate, so dropping/re-adding the
    // parity byte must not change a single byte of the resulting PSBT.
    const fromXpub = buildBip322Bundle({
      message: 'POR',
      descriptor: `tr([0f056943]${simXpub}/0/0)`,
    });
    const fromXOnly = buildBip322Bundle({
      message: 'POR',
      descriptor: `tr([0f056943/0/0]${xonly})`,
    });
    expect(fromXOnly.psbtBase64).toBe(fromXpub.psbtBase64);
  });

  it('a 33-byte compressed key and its x-only form are equivalent in tr()', () => {
    const fromCompressed = buildBip322Bundle({
      message: 'POR',
      descriptor: `tr([0f056943/0/0]${compressed})`,
    });
    const fromXOnly = buildBip322Bundle({
      message: 'POR',
      descriptor: `tr([0f056943/0/0]${xonly})`,
    });
    expect(fromXOnly.psbtBase64).toBe(fromCompressed.psbtBase64);
  });

  it('rejects a child path after a bare x-only key', () => {
    expect(() => parseDescriptor(`tr([0f056943]${xonly}/0/0)`)).toThrow(
      /bare public key cannot have a child/i,
    );
  });
});

describe('UTXO type override', () => {
  const xpub =
    'xpub661MyMwAqRbcGC9DmWbtbAmuUjpMYxw4BWE88NSDHB3jSjfUK7KtYJuKa52GbowD3DVLkgsxH9QwPnTx5mjdHykYFEncnmAsNsCTbWzBhA7';

  it('auto-picks witness for native segwit (wpkh)', () => {
    const r = buildBip322Bundle({
      message: 'POR',
      descriptor: `wpkh([0f056943]${xpub}/0/0)`,
    });
    expect(r.utxoType).toBe('witness');
  });

  it('auto-picks non_witness for legacy (pkh)', () => {
    const r = buildBip322Bundle({
      message: 'POR',
      descriptor: `pkh([0f056943]${xpub}/0/0)`,
    });
    expect(r.utxoType).toBe('non_witness');
  });

  it('honors explicit utxoType override', () => {
    const wpkhDesc = `wpkh([0f056943]${xpub}/0/0)`;
    const auto = buildBip322Bundle({ message: 'POR', descriptor: wpkhDesc });
    const forced = buildBip322Bundle({
      message: 'POR',
      descriptor: wpkhDesc,
      utxoType: 'non_witness',
    });
    expect(auto.utxoType).toBe('witness');
    expect(forced.utxoType).toBe('non_witness');
    expect(auto.psbtBase64).not.toBe(forced.psbtBase64);
  });
});

describe('BIP-322 message hash', () => {
  it('uses BIP-340-style double-tagged hash', () => {
    // tagged_hash("BIP0322-signed-message", b"") computed independently:
    // tag = sha256(b"BIP0322-signed-message"); sha256(tag||tag||"")
    // Python one-liner:
    //   hashlib.sha256(hashlib.sha256(b"BIP0322-signed-message").digest()*2).hexdigest()
    const got = bip322MsgHash(new Uint8Array(0));
    expect(Buffer.from(got).toString('hex')).toBe(
      'c90c269c4f8fcbe6880f72a721ddfbf1914268a794cbb21cfafee13770ae19f1',
    );
  });
});
