# BIP-322 PSBT Creator

A static, browser-only tool that constructs unsigned
[BIP-322](https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki) PSBTs
for hardware wallets to sign. Paste a message and an output descriptor; out
comes the unsigned PSBT (base64, `.psbt` file, plain QR, or animated BBQr).
Sign the PSBT with your hardware wallet — the signed result is a portable
proof you control the address: proof of reserves, exchange attestations, or
any "I own this address" claim.

The tool only needs the **public** descriptor — no keys are entered. The page
ships with a strict Content-Security-Policy (`connect-src 'none'`) so the
browser will refuse any outbound `fetch` / XHR / WebSocket at runtime; all
JS, CSS, and assets load from `self`.

## Supported

- **Single-sig** descriptors: `pkh(...)`, `wpkh(...)`, `sh(wpkh(...))`,
  `tr(...)` (BIP-86 key-path; no script tree)
- **Non-taproot multisig**: `sh(multi(...))`, `wsh(multi(...))`,
  `sh(wsh(multi(...)))`, and each of these with `sortedmulti` (BIP-67) in
  place of `multi`
- **Networks**: mainnet and testnet, auto-detected from the xpub version bytes
- **PSBT version**: v0
- **Output formats**: base64 (text), `.psbt` (binary file), plain QR code,
  animated BBQr (multi-frame, used automatically for payloads that won't fit
  in a single QR)
- **QR scanner** for Coldcard Q's *Key Expression* export — paste-free
  descriptor input (lazy-loaded webcam decoder)

## Out of scope

Taproot multisig (`multi_a` / `sortedmulti_a`), multi-input proof-of-reserves
PSBTs, PSBT v2 output, sighash overrides, in-browser signing, wallet-connect
flows, and verification of received signed proofs (verification is a planned
follow-up — see the `/verify` deferred plan in `~/.claude/projects/.../memory`).

## Descriptor format

### Single-sig

```
wpkh([d34db33f/84h/0h/0h]xpub6.../0/0)
   ^   ^         ^         ^      ^
   |   |         |         |      └── concrete child path (non-hardened, no /*)
   |   |         |         └────────── account xpub
   |   |         └──────────────────── path from master to that xpub
   |   └────────────────────────────── master fingerprint (8 hex chars)
   └────────────────────────────────── script type
```

The `[origin]` block is **optional** — if omitted, the fingerprint emitted in
the PSBT's `BIP32_DERIVATION` field is computed as `hash160(xpub.pubkey)[:4]`
per BIP-32. For a master xpub this matches what an explicit origin would have
carried; for a non-master xpub it falls back to that xpub's own fingerprint
(the best a signer can do without origin metadata).

### Multisig

```
wsh(sortedmulti(2,[fp1/48h/0h/0h/2h]xpub.../0/0,[fp2/...]xpub.../0/0,[fp3/...]xpub.../0/0))
```

Each cosigner key uses the same `[origin]xpub/.../i/j` form (origin optional
per the rule above). Use `multi` in place of `sortedmulti` if you want
descriptor-order keys; `sortedmulti` lexicographically sorts the derived
pubkeys per BIP-67. `M` ∈ `1..16`, `N` ∈ `1..16`, `M ≤ N`.

An optional `#xxxxxxxx` checksum suffix is accepted but **not validated**.

## `witness_utxo` vs `non_witness_utxo`

BIP-322's *PSBT creator* role (BIP-322 §"PSBT creator", step 4) says to set
the appropriate `witness_utxo` / `non_witness_utxo` field. By default the
page picks per BIP-174 idiom:

| Script type | Default field |
|---|---|
| `pkh`, `sh-multi` | `PSBT_IN_NON_WITNESS_UTXO` (full `to_spend` serialized) |
| `wpkh`, `sh-wpkh`, `tr`, `wsh-multi`, `sh-wsh-multi` | `PSBT_IN_WITNESS_UTXO` (the `to_spend.vout[0]` only) |

The output panel exposes a `utxo` / `wutxo` radio toggle so you can override
the choice if you need to match a specific signer's expectations.

## Worked example

Input:

- Message: `POR`
- Descriptor:
  ```
  wpkh([0f056943]xpub661MyMwAqRbcGC9DmWbtbAmuUjpMYxw4BWE88NSDHB3jSjfUK7KtYJuKa52GbowD3DVLkgsxH9QwPnTx5mjdHykYFEncnmAsNsCTbWzBhA7/0/0)
  ```

Output (base64 PSBT):

```
cHNidP8BAD0AAAAAAUnXZH6/9Ef3a+yDzMgzyWIFbHDGWB1qHFZt250BqcKUAAAAAAD/////AQAAAAAAAAAAAWoAAAAAAQkDUE9SAAEBHwAAAAAAAAAAFgAUCyU3p9bzzGaMnp+gMD/7PK1um4EiBgMr43KAHYRg3aUq4Xiq13SlSAC6VvlJyXuKL1HimSCdBgwPBWlDAAAAAAAAAAAAAA==
```

This is the same value committed in `test/fixtures.json` under
`mainnet-wpkh-default`. The recovered address is
`bc1qpvjn0f7k70xxdry7n7srq0lm8jkkaxupfk25ew`.

## Local development

```
npm install
npm run dev          # http://localhost:5173
npm test             # 60 tests: 24 single-sig + 18 multisig byte-equality
                     # fixtures plus parser / hash / utxo-override unit tests
npm run build        # produces ./dist
```

## Deploying to GitHub Pages

`.github/workflows/pages.yml` builds and deploys on push to `main`. On first
setup:

1. **Settings → Pages**: set **Source = "GitHub Actions"** (not "Deploy from
   a branch"). The workflow uses `actions/deploy-pages`, which only works
   with the Actions source.
2. Push to `main`. The workflow installs deps, runs the test suite, builds
   with Vite, and publishes `./dist`.

`vite.config.js` sets `base: './'`, so the bundle works at any subpath
(e.g. `https://you.github.io/repo-name/`).

## Regenerating test fixtures

The 24 single-sig fixtures (`test/fixtures.json`) and 18 multisig fixtures
(`test/ms_fixtures.json`) are produced by the helper scripts in `scripts/`:

```
python scripts/gen_fixtures.py
python scripts/gen_ms_fixtures.py
```

Each script imports an independent Python BIP-322 implementation as a
cross-check oracle; see the top of each file for the expected path and
adjust it for your layout.

## How it works

Given a descriptor that resolves to scriptPubKey `spk`, message bytes `msg`,
and BIP32 derivation info per key `(fp, path, pubkey)`:

1. `msg_hash = sha256(tag || tag || msg)`, where `tag = sha256("BIP0322-signed-message")`.
2. **`to_spend`** (virtual funding tx, never broadcast):
   - `nVersion = 0`, `nLockTime = 0`
   - vin: `prev_txid = 0x00 * 32`, `prev_vout = 0xffffffff`, `scriptSig = OP_0 PUSH32 msg_hash`, `nSequence = 0`
   - vout: `value = 0`, `scriptPubKey = spk`
3. **`to_sign`** (the PSBT's unsigned tx):
   - `nVersion = 0`, `nLockTime = 0`
   - vin: spends `to_spend:0`, `nSequence = 0xffffffff`
   - vout: one `value = 0`, `scriptPubKey = 0x6a` (bare `OP_RETURN`)
4. PSBT v0 globals:
   - `PSBT_GLOBAL_UNSIGNED_TX = to_sign`
   - `PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE = msg` (BIP-322 key `0x09`)
5. PSBT input map (one input, since the page only handles single-input proofs):
   - **UTXO field** per the table above — `PSBT_IN_NON_WITNESS_UTXO` for bare
     legacy types, `PSBT_IN_WITNESS_UTXO` for anything segwit, override via UI
   - `sh(wpkh(...))`: `PSBT_IN_REDEEM_SCRIPT`
   - `sh(multi(...))`: `PSBT_IN_REDEEM_SCRIPT = multisig redeem script`
   - `wsh(multi(...))`: `PSBT_IN_WITNESS_SCRIPT = multisig redeem script`
   - `sh(wsh(multi(...)))`: both — `PSBT_IN_REDEEM_SCRIPT = OP_0 PUSH32 sha256(witness_script)` and `PSBT_IN_WITNESS_SCRIPT = witness_script`
   - All non-taproot: one `PSBT_IN_BIP32_DERIVATION` per cosigner (in pubkey
     order if the descriptor is `sortedmulti`, otherwise descriptor order)
   - Taproot: one `PSBT_IN_TAP_BIP32_DERIVATION` with an empty leaf-hash list

For byte-level disputes the test suite cross-checks JS output against the
Python oracle invoked from `scripts/gen_*.py`.

## License

ISC.
