#!/usr/bin/env python3
# Generate BIP-322 multisig PSBT fixtures by re-doing the single-input
# branch of bip322_ms_txn() from afirmware/testing/bip322.py against three
# known cosigner masters.

import hashlib
import json
import struct
import sys
from base64 import b64encode
from io import BytesIO
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
AFW = REPO.parent / "afirmware" / "testing"
sys.path.insert(0, str(AFW))

from bip32 import BIP32Node  # noqa: E402
from ctransaction import CTransaction, COutPoint, CTxIn, CTxOut  # noqa: E402
from psbt import BasicPSBT, BasicPSBTInput, BasicPSBTOutput  # noqa: E402
from helpers import hash160  # noqa: E402

# Three distinct cosigner masters with three distinct fingerprints.
COSIGNERS_MAIN = [
    # BIP-32 test vector 1
    ("vec1",
     "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
     "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"),
    # BIP-32 test vector 2
    ("vec2",
     "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U",
     "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"),
    # Simulator xprv (xfp = 0f056943)
    ("sim",
     "xprv9s21ZrQH143K3i4kfV4tE2qAvhys9WDCpHJXKz2biqWkZwLKma1dzWaqin8CxCKPF3tX2fVRD9tBggJtxvdAxTpKfz8zRUoJZa3S7MtMgwy",
     "xpub661MyMwAqRbcGC9DmWbtbAmuUjpMYxw4BWE88NSDHB3jSjfUK7KtYJuKa52GbowD3DVLkgsxH9QwPnTx5mjdHykYFEncnmAsNsCTbWzBhA7"),
]


def bip322_msg_hash(msg: bytes) -> bytes:
    tag_hash = hashlib.sha256(b"BIP0322-signed-message").digest()
    return hashlib.sha256(tag_hash + tag_hash + msg).digest()


def make_multisig(M, cosigners, sub_path: str, sorted_):
    """Returns (script, spk_redeem_witness, details).
    details: list of (pubkey_bytes, xfp_bytes, full_path_steps[int]) in PSBT
             insertion order (sorted by pubkey if sorted_)."""
    derived = []
    for label, xprv, _xpub in cosigners:
        mk = BIP32Node.from_wallet_key(xprv)
        xfp = mk.fingerprint()
        sub = mk.subkey_for_path(sub_path)
        pk = sub.sec()
        # Path from master is just the sub_path here.
        steps = []
        for p in sub_path.split("/"):
            if not p or p == "m":
                continue
            if p.endswith("h") or p.endswith("'"):
                steps.append(int(p[:-1]) | 0x80000000)
            else:
                steps.append(int(p))
        derived.append((pk, xfp, steps))
    if sorted_:
        derived.sort(key=lambda x: x[0])
    return derived


def build_multisig_redeem(M, derived):
    mm = bytes([0x50 + M])
    nn = bytes([0x50 + len(derived)])
    parts = [mm]
    for pk, _, _ in derived:
        parts.append(bytes([len(pk)]) + pk)
    parts.append(nn + bytes([0xae]))
    return b"".join(parts)


def appropriate_utxo(addr_fmt: str) -> str:
    """BIP-322 step 4 'appropriate' choice: bare legacy P2SH -> non_witness,
    segwit (wsh, sh-wsh) -> witness."""
    if addr_fmt == "sh":
        return "non_witness"
    return "witness"


def build_psbt(M, cosigners, sub_path, addr_fmt, msg, sorted_):
    derived = make_multisig(M, cosigners, sub_path, sorted_)
    script = build_multisig_redeem(M, derived)

    if addr_fmt == "wsh":
        scriptPubKey = bytes([0x00, 0x20]) + hashlib.sha256(script).digest()
        psbt_redeem = None
        psbt_witness = script
    elif addr_fmt == "sh":
        scriptPubKey = bytes([0xa9, 0x14]) + hash160(script) + bytes([0x87])
        psbt_redeem = script
        psbt_witness = None
    elif addr_fmt == "sh-wsh":
        inner = b"\x00\x20" + hashlib.sha256(script).digest()
        scriptPubKey = bytes([0xa9, 0x14]) + hash160(inner) + bytes([0x87])
        psbt_redeem = inner
        psbt_witness = script
    else:
        raise ValueError(addr_fmt)

    psbt = BasicPSBT()
    psbt.bip322_msg = msg
    psbt.inputs = [BasicPSBTInput(idx=0)]
    psbt.outputs = [BasicPSBTOutput(idx=0)]

    if psbt_redeem is not None:
        psbt.inputs[0].redeem_script = psbt_redeem
    if psbt_witness is not None:
        psbt.inputs[0].witness_script = psbt_witness

    for pubkey, xfp, steps in derived:
        psbt.inputs[0].bip32_paths[pubkey] = xfp + b"".join(
            struct.pack("<I", s) for s in steps
        )

    # to_spend
    to_spend = CTransaction()
    to_spend.nVersion = 0
    out_point = COutPoint(hash=0, n=0xffffffff)
    msg_hash = bip322_msg_hash(msg)
    to_spend.vin = [CTxIn(out_point, scriptSig=b"\x00\x20" + msg_hash)]
    to_spend.vout.append(CTxOut(0, scriptPubKey))
    to_spend.calc_sha256()
    if appropriate_utxo(addr_fmt) == "witness":
        psbt.inputs[0].witness_utxo = to_spend.vout[0].serialize()
    else:
        psbt.inputs[0].utxo = to_spend.serialize_with_witness()

    # to_sign
    to_sign = CTransaction()
    to_sign.nVersion = 0
    to_sign.vin.append(CTxIn(COutPoint(to_spend.sha256, 0), nSequence=0xffffffff))
    to_sign.vout.append(CTxOut(0, b"\x6a"))

    psbt.txn = to_sign.serialize_with_witness()

    rv = BytesIO()
    psbt.serialize(rv)
    return rv.getvalue(), scriptPubKey


def fp_hex(xprv):
    return BIP32Node.from_wallet_key(xprv).fingerprint().hex()


def descriptor_for(addr_fmt, M, cosigners, sub_path, sortedflag):
    multi_word = "sortedmulti" if sortedflag else "multi"
    parts = [str(M)]
    for label, xprv, xpub in cosigners:
        parts.append(f"[{fp_hex(xprv)}]{xpub}/{sub_path}")
    body = ",".join(parts)
    inner = f"{multi_word}({body})"
    if addr_fmt == "wsh":
        return f"wsh({inner})"
    if addr_fmt == "sh":
        return f"sh({inner})"
    if addr_fmt == "sh-wsh":
        return f"sh(wsh({inner}))"
    raise ValueError(addr_fmt)


fixtures = []
SUB = "0/0"
M = 2

for sortedflag in (True, False):
    for addr_fmt in ("sh", "wsh", "sh-wsh"):
        for msg_name, msg in [
            ("default", b"POR"),
            ("empty", b""),
            ("long", b"Multisig BIP-322 proof from 2-of-3."),
        ]:
            psbt_bytes, _ = build_psbt(
                M, COSIGNERS_MAIN, SUB, addr_fmt, msg, sortedflag
            )
            descriptor = descriptor_for(addr_fmt, M, COSIGNERS_MAIN, SUB, sortedflag)
            type_str = {"sh": "sh-multi", "wsh": "wsh-multi", "sh-wsh": "sh-wsh-multi"}[addr_fmt]
            fixtures.append({
                "name": f"{'sortedmulti' if sortedflag else 'multi'}-{addr_fmt}-{msg_name}",
                "network": "mainnet",  # xpubs above are all mainnet
                "type": type_str,
                "m": M,
                "n": len(COSIGNERS_MAIN),
                "sorted": sortedflag,
                "descriptor": descriptor,
                "message_hex": msg.hex(),
                "expected_psbt_base64": b64encode(psbt_bytes).decode(),
            })

out_path = REPO / "test" / "ms_fixtures.json"
with open(out_path, "w") as f:
    json.dump(fixtures, f, indent=2)
print(f"Wrote {len(fixtures)} multisig fixtures to {out_path}")
