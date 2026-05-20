#!/usr/bin/env python3
# Generate BIP-322 PSBT fixtures using the Coinkite test reference
# (afirmware/testing/bip322.py). Run with the afirmware_env venv.
#
# Output: test/fixtures.json — each entry has the inputs we feed the JS
# (descriptor + message + network) and the expected PSBT base64.

import json
import os
import struct
import sys
import hashlib
from io import BytesIO
from base64 import b64encode
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
AFW = REPO.parent / "afirmware" / "testing"
sys.path.insert(0, str(AFW))

from bip32 import BIP32Node, PublicKey
from ctransaction import CTransaction, COutPoint, CTxIn, CTxOut, uint256_from_str
from psbt import BasicPSBT, BasicPSBTInput, BasicPSBTOutput
from helpers import hash160, taptweak, str_to_path
from constants import simulator_fixed_xprv, simulator_fixed_xpub, simulator_fixed_tprv, simulator_fixed_tpub


def bip322_msg_hash(msg: bytes) -> bytes:
    tag_hash = hashlib.sha256(b"BIP0322-signed-message").digest()
    return hashlib.sha256(tag_hash + tag_hash + msg).digest()


def build_psbt(master_key: str, sub_path: str, addr_fmt: str, msg: bytes) -> bytes:
    """Minimal single-input port of bip322_txn(...) from afirmware/testing/bip322.py.
    Uses witness_utxo=[] (default), psbt_v2=False, one input."""
    psbt = BasicPSBT()
    psbt.bip322_msg = msg

    to_sign = CTransaction()
    to_sign.nLockTime = 0
    to_sign.nVersion = 0

    mk = BIP32Node.from_wallet_key(master_key)
    mfp = mk.fingerprint()

    psbt.inputs = [BasicPSBTInput(idx=0)]
    psbt.outputs = []

    int_path = str_to_path(sub_path)
    sec = mk.subkey_for_path(sub_path).sec()
    assert len(sec) == 33
    subkey = PublicKey.parse(sec)

    if addr_fmt == "p2tr":
        tweaked_xonly = taptweak(sec[1:])
        psbt.inputs[0].taproot_bip32_paths[sec[1:]] = (
            b"\x00" + mfp + struct.pack(f'<{"I" * len(int_path)}', *int_path)
        )
        scr = bytes([81, 32]) + tweaked_xonly
    elif addr_fmt == "p2wpkh":
        psbt.inputs[0].bip32_paths[sec] = mfp + struct.pack(
            f'<{"I" * len(int_path)}', *int_path
        )
        scr = bytes([0x00, 0x14]) + subkey.h160()
    elif addr_fmt in ("p2sh-p2wpkh", "p2wpkh-p2sh"):
        psbt.inputs[0].bip32_paths[sec] = mfp + struct.pack(
            f'<{"I" * len(int_path)}', *int_path
        )
        inner = bytes([0x00, 0x14]) + subkey.h160()
        psbt.inputs[0].redeem_script = inner
        scr = bytes([0xa9, 0x14]) + hash160(inner) + bytes([0x87])
    elif addr_fmt == "p2pkh":
        psbt.inputs[0].bip32_paths[sec] = mfp + struct.pack(
            f'<{"I" * len(int_path)}', *int_path
        )
        scr = bytes([0x76, 0xa9, 0x14]) + subkey.h160() + bytes([0x88, 0xac])
    else:
        raise ValueError(addr_fmt)

    # to_spend
    to_spend = CTransaction()
    to_spend.nVersion = 0
    out_point = COutPoint(hash=0, n=0xffffffff)
    msg_hash = bip322_msg_hash(msg)
    to_spend.vin = [CTxIn(out_point, scriptSig=b"\x00\x20" + msg_hash)]
    to_spend.vout = [CTxOut(0, scr)]
    to_spend.calc_sha256()

    psbt.inputs[0].utxo = to_spend.serialize_with_witness()

    spendable = CTxIn(COutPoint(to_spend.sha256, 0), nSequence=0xffffffff)
    to_sign.vin.append(spendable)

    # one OP_RETURN output
    psbt.outputs.append(BasicPSBTOutput(idx=0))
    to_sign.vout.append(CTxOut(0, b"\x6a"))

    psbt.txn = to_sign.serialize_with_witness()

    rv = BytesIO()
    psbt.serialize(rv)
    return rv.getvalue()


# --- generate fixtures ---

# Mainnet master xpub from simulator_fixed_xprv (so we can put it inside the descriptor)
MAINNET_XPUB = simulator_fixed_xpub
TESTNET_XPUB = simulator_fixed_tpub

# The master fingerprint is hash160(master_pubkey)[:4]; recompute it for the descriptor.
def fingerprint_hex(xprv_or_xpub: str) -> str:
    mk = BIP32Node.from_wallet_key(xprv_or_xpub)
    return mk.fingerprint().hex()

MAINNET_FP = fingerprint_hex(simulator_fixed_xprv)
TESTNET_FP = fingerprint_hex(simulator_fixed_tprv)

cases = [
    ("mainnet", "p2pkh",      "pkh"),
    ("mainnet", "p2wpkh",     "wpkh"),
    ("mainnet", "p2sh-p2wpkh", "sh-wpkh"),
    ("mainnet", "p2tr",       "tr"),
    ("testnet", "p2pkh",      "pkh"),
    ("testnet", "p2wpkh",     "wpkh"),
    ("testnet", "p2sh-p2wpkh", "sh-wpkh"),
    ("testnet", "p2tr",       "tr"),
]

MESSAGES = {
    "default": b"POR",
    "long":    b"Hello, BIP-322! A slightly longer test message.",
    "empty":   b"",
}

fixtures = []

for network, py_addr_fmt, js_type in cases:
    master_xprv = simulator_fixed_xprv if network == "mainnet" else simulator_fixed_tprv
    master_xpub = MAINNET_XPUB if network == "mainnet" else TESTNET_XPUB
    fp = MAINNET_FP if network == "mainnet" else TESTNET_FP

    for msg_name, msg in MESSAGES.items():
        sub_path = "0/0"
        psbt_bytes = build_psbt(master_xprv, sub_path, py_addr_fmt, msg)
        psbt_b64 = b64encode(psbt_bytes).decode()

        if js_type == "sh-wpkh":
            descriptor = f"sh(wpkh([{fp}]{master_xpub}/{sub_path}))"
        else:
            descriptor = f"{js_type}([{fp}]{master_xpub}/{sub_path})"

        fixtures.append({
            "name": f"{network}-{js_type}-{msg_name}",
            "network": network,
            "type": js_type,
            "descriptor": descriptor,
            "message_hex": msg.hex(),
            "expected_psbt_base64": psbt_b64,
        })

out_path = REPO / "test" / "fixtures.json"
out_path.parent.mkdir(exist_ok=True)
with open(out_path, "w") as f:
    json.dump(fixtures, f, indent=2)

print(f"Wrote {len(fixtures)} fixtures to {out_path}")
