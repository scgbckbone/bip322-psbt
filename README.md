# BIP-322 PSBT Builder

A static, browser-only tool that constructs unsigned **BIP-322** PSBTs for
hardware wallets to sign. Paste a message and an output descriptor, get a
base64-encoded PSBT.

Nothing leaves the page — no keys are ever entered (the tool only needs the
**public** descriptor), and no network requests are made at runtime.

## Supported

- Single-sig descriptors: `pkh(...)`, `wpkh(...)`, `sh(wpkh(...))`, `tr(...)` (BIP-86 key-path, no script tree)
- Networks: **mainnet** and **testnet** (auto-detected from the xpub version bytes)
- Output: PSBT v0 as base64

## Out of scope (v1)

Multisig, multi-input proof-of-reserves, PSBT v2, QR / file output, sighash
overrides, signing in the browser, wallet connection.

## Descriptor format

```
wpkh([d34db33f/84h/0h/0h]xpub6.../0/0)
   ^   ^         ^         ^      ^
   |   |         |         |      └── concrete child path (non-hardened, no /*)
   |   |         |         └────────── account xpub
   |   |         └──────────────────── path from master to that xpub
   |   └────────────────────────────── master fingerprint (8 hex chars)
   └────────────────────────────────── script type
```

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

This output matches Coinkite's Python reference implementation
(`afirmware/testing/bip322.py`) byte-for-byte.

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

The 24 expected outputs in `test/fixtures.json` come from the Python
reference. To regenerate them:

```
/path/to/afirmware/venv/bin/python scripts/gen_fixtures.py
```

The script expects `afirmware/testing/` to live at `../afirmware/testing/`
relative to this repo. Adjust the `AFW` path in `scripts/gen_fixtures.py` if
your layout differs.

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
   types), `PSBT_IN_REDEEM_SCRIPT` (sh-wpkh only), and either
   `PSBT_IN_BIP32_DERIVATION` (non-taproot) or
   `PSBT_IN_TAP_BIP32_DERIVATION` (taproot, with empty leaf-hash list).

The Python reference at `afirmware/testing/bip322.py` is the tiebreaker for
any byte-level question.

## License

ISC.
