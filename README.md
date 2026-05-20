# BIP-322 PSBT Creator

A static, browser-only tool that constructs unsigned **BIP-322** PSBTs for
hardware wallets to sign. Paste a message and an output descriptor, get a
base64-encoded PSBT.

Nothing leaves the page — no keys are ever entered (the tool only needs the
**public** descriptor), and no network requests are made at runtime.

## Supported

- Single-sig descriptors: `pkh(...)`, `wpkh(...)`, `sh(wpkh(...))`, `tr(...)` (BIP-86 key-path, no script tree)
- Non-taproot multisig: `sh(multi(...))`, `wsh(multi(...))`, `sh(wsh(multi(...)))` and the `sortedmulti` (BIP-67) equivalents
- Networks: **mainnet** and **testnet** (auto-detected from the xpub version bytes)
- Output: PSBT v0 as base64

## Out of scope

Taproot multisig (`multi_a` / `sortedmulti_a`), multi-input proof-of-reserves,
PSBT v2, QR / file output, sighash overrides, signing in the browser, wallet
connection.

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

### Multisig

```
wsh(sortedmulti(2,[fp1/48h/0h/0h/2h]xpub6.../0/0,[fp2/...]xpub.../0/0,[fp3/...]xpub.../0/0))
```

Each cosigner key uses the same `[origin]xpub/.../i/j` form as the single-sig
case. Replace `sortedmulti` with `multi` if you want descriptor-order keys
(the BIP-67 sort is skipped). M must be in `1..16`, N must be in `1..16`,
M ≤ N.

An optional `#xxxxxxxx` checksum suffix is accepted but **not validated**.

## Worked example

Input:

- Message: `POR`
- Descriptor:
  ```
  wpkh([0f056943]xpub661MyMwAqRbcGC9DmWbtbAmuUjpMYxw4BWE88NSDHB3jSjfUK7KtYJuKa52GbowD3DVLkgsxH9QwPnTx5mjdHykYFEncnmAsNsCTbWzBhA7/0/0)
  ```

Output (base64 PSBT):

```
cHNidP8BAD0AAAAAAUnXZH6/9Ef3a+yDzMgzyWIFbHDGWB1qHFZt250BqcKUAAAAAAD/////AQAAAAAAAAAAAWoAAAAAAQkDUE9SAAEAdAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/////IgAgEbX+NXhC9cNo0uOITWpbpXfjvHzeEyAE85uMKkOpzewAAAAAAQAAAAAAAAAAFgAUCyU3p9bzzGaMnp+gMD/7PK1um4EAAAAAIgYDK+NygB2EYN2lKuF4qtd0pUgAulb5Scl7ii9R4pkgnQYMDwVpQwAAAAAAAAAAAAA=
```

This output is locked down by byte-equality tests against pre-generated
fixtures (`test/fixtures.json`, `test/ms_fixtures.json`).

## Local development

```
npm install
npm run dev          # http://localhost:5173
npm test             # 32 tests against the Python reference fixtures
npm run build        # produces ./dist
```

## Deploying to GitHub Pages

The repo includes `.github/workflows/pages.yml`. On the first push to `main`:

1. In your repo's **Settings → Pages**, set **Source = "GitHub Actions"**.
2. Push. The workflow builds with Vite, runs the tests, and publishes
   `./dist` to Pages.

The Vite build uses `base: './'` so the bundle works at any subpath
(`https://you.github.io/repo-name/`).

## Regenerating test fixtures

The 24 single-sig fixtures in `test/fixtures.json` and the 18 multisig
fixtures in `test/ms_fixtures.json` are produced by the helper scripts in
`scripts/`:

```
python scripts/gen_fixtures.py
python scripts/gen_ms_fixtures.py
```

The scripts pull in a separate Python BIP-322 implementation as an
independent oracle; see the top of each script for the expected path and
adjust it for your layout.

## How it works

For a single-sig descriptor with scriptPubKey `spk`, message bytes `msg`,
and BIP32 derivation info `(fp, path, pubkey)`:

1. `msg_hash = sha256(tag || tag || msg)` where `tag = sha256("BIP0322-signed-message")`.
2. **to_spend** (virtual funding tx):
   - `nVersion=0`, `nLockTime=0`
   - vin: `prev_txid = 0x00*32`, `prev_vout = 0xffffffff`, `scriptSig = OP_0 PUSH32 msg_hash`, `nSequence = 0`
   - vout: `value=0`, `scriptPubKey = spk`
3. **to_sign** (the PSBT's unsigned tx):
   - `nVersion=0`, `nLockTime=0`
   - vin: spends `to_spend:0`, `nSequence = 0xffffffff`
   - vout: one `value=0` `scriptPubKey=0x6a` (bare OP_RETURN)
4. PSBT v0 globals: `PSBT_GLOBAL_UNSIGNED_TX = to_sign`, `PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE = msg`.
5. PSBT input map: `PSBT_IN_NON_WITNESS_UTXO = to_spend` (for all address
   types). Per-type additions:
   - `sh(wpkh(...))`: `PSBT_IN_REDEEM_SCRIPT`
   - `sh(multi(...))`: `PSBT_IN_REDEEM_SCRIPT = multisig redeem script`
   - `wsh(multi(...))`: `PSBT_IN_WITNESS_SCRIPT = multisig redeem script`
   - `sh(wsh(multi(...)))`: both — `PSBT_IN_REDEEM_SCRIPT = OP_0 PUSH32 sha256(witnessScript)` and `PSBT_IN_WITNESS_SCRIPT = multisig redeem script`
   - All non-taproot types: one `PSBT_IN_BIP32_DERIVATION` per cosigner pubkey
   - Taproot: one `PSBT_IN_TAP_BIP32_DERIVATION` with empty leaf-hash list

[BIP-322](https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki) is
the spec. For byte-level disputes the test suite cross-checks against an
independent Python implementation invoked from `scripts/gen_*.py`.

## License

ISC.
