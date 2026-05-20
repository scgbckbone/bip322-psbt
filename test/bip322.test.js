import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { buildBip322Bundle } from '../src/bip322.js';
import { parseDescriptor } from '../src/descriptor.js';
import { fromHex } from '../src/util.js';
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
