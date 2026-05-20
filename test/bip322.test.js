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

describe('BIP-322 PSBT — byte-for-byte vs Python reference', () => {
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

describe('descriptor parser', () => {
  const xpub =
    'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8';

  it('rejects empty input', () => {
    expect(() => parseDescriptor('')).toThrow();
  });

  it('rejects missing origin', () => {
    expect(() => parseDescriptor(`wpkh(${xpub}/0/0)`)).toThrow(/origin/i);
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
