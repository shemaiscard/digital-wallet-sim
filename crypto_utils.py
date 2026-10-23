"""Keys, passphrases and signatures for the simulated wallet.

- Recovery phrase: 12 BIP39 words (128 bits), shown once and never stored.
- Keys: BIP32 derivation from the BIP39 seed along m/44'/1'/0'/0/0 (coin type 1 is
  the SLIP-44 testnet type, a reminder that these coins have no value).
- Login passphrase: random words from the EFF large word list (7,776 words, about
  12.9 bits per word), independent of the recovery phrase.
- Stored secrets: the passphrase as an Argon2id hash, and the private key encrypted
  with AES-256-GCM under a key that Argon2id derives from the passphrase.
"""
import binascii
import hashlib
import hmac
import json
import math
import os
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from mnemonic import Mnemonic

CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
HARDENED = 0x80000000
WALLET_PATH = "m/44'/1'/0'/0/0"

# Argon2id cost, RFC 9106's second recommended option with one lane: 3 passes over 64 MiB.
ARGON2 = {"time_cost": 3, "memory_cost": 64 * 1024, "parallelism": 1}
PASSPHRASE_WORDS = 6

_HERE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(_HERE, "eff_large_wordlist.txt"), encoding="utf-8") as _f:
    WORDLIST = [line.split()[1] for line in _f if line.strip()]
assert len(WORDLIST) == 7776

_hasher = PasswordHasher(**ARGON2)


# ---------------------------------------------------------------- recovery phrase and BIP32
def new_recovery_phrase():
    return Mnemonic("english").generate(strength=128)


def valid_recovery_phrase(phrase):
    return Mnemonic("english").check(" ".join(phrase.lower().split()))


def seed_from_phrase(phrase):
    return Mnemonic.to_seed(" ".join(phrase.lower().split()), passphrase="")


def _pub_compressed(k):
    key = ec.derive_private_key(k, ec.SECP256K1())
    return key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)


def master_key(seed):
    i = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    k = int.from_bytes(i[:32], "big")
    if not 0 < k < CURVE_ORDER:
        raise ValueError("invalid master key")
    return k, i[32:]


def child_key(k, chain, index):
    """BIP32 private child key derivation (CKDpriv)."""
    if index >= HARDENED:
        data = b"\x00" + k.to_bytes(32, "big") + index.to_bytes(4, "big")
    else:
        data = _pub_compressed(k) + index.to_bytes(4, "big")
    i = hmac.new(chain, data, hashlib.sha512).digest()
    il = int.from_bytes(i[:32], "big")
    child = (il + k) % CURVE_ORDER
    if il >= CURVE_ORDER or child == 0:
        raise ValueError("invalid child key; use the next index")
    return child, i[32:]


def derive_path(seed, path=WALLET_PATH):
    k, chain = master_key(seed)
    for part in path.split("/")[1:]:
        idx = int(part.rstrip("'")) + (HARDENED if part.endswith("'") else 0)
        k, chain = child_key(k, chain, idx)
    return k


def keys_from_phrase(phrase):
    """Returns (private key hex, compressed public key hex)."""
    k = derive_path(seed_from_phrase(phrase))
    return k.to_bytes(32, "big").hex(), _pub_compressed(k).hex()


def address_from_public_key(public_key_hex):
    """Simulation address: 0x + the first 40 hex digits of double SHA-256 of the public key."""
    h = hashlib.sha256(hashlib.sha256(binascii.unhexlify(public_key_hex)).digest()).hexdigest()
    return "0x" + h[:40]


# ---------------------------------------------------------------- login passphrase
def new_passphrase(words=PASSPHRASE_WORDS):
    return " ".join(secrets.choice(WORDLIST) for _ in range(words))


def passphrase_bits(words=PASSPHRASE_WORDS):
    return words * math.log2(len(WORDLIST))


def normalize_passphrase(text):
    return " ".join(text.lower().split())


def hash_passphrase(passphrase):
    return _hasher.hash(normalize_passphrase(passphrase))


def check_passphrase(stored_hash, passphrase):
    try:
        return _hasher.verify(stored_hash, normalize_passphrase(passphrase))
    except (VerificationError, InvalidHashError):
        return False


# ---------------------------------------------------------------- encrypted key store
def _kek(passphrase, salt):
    return hash_secret_raw(normalize_passphrase(passphrase).encode(), salt, hash_len=32, type=Type.ID, **ARGON2)


def encrypt_private_key(private_key_hex, passphrase, username):
    salt, nonce = os.urandom(16), os.urandom(12)
    ct = AESGCM(_kek(passphrase, salt)).encrypt(nonce, bytes.fromhex(private_key_hex), username.encode())
    return {"v": 1, "kdf": "argon2id", "kdf_params": ARGON2, "salt": salt.hex(), "nonce": nonce.hex(), "ct": ct.hex()}


def decrypt_private_key(keystore, passphrase, username):
    """Returns the private key hex, or None if the passphrase is wrong."""
    try:
        key = _kek(passphrase, bytes.fromhex(keystore["salt"]))
        pt = AESGCM(key).decrypt(bytes.fromhex(keystore["nonce"]), bytes.fromhex(keystore["ct"]), username.encode())
        return pt.hex()
    except Exception:
        return None


# ---------------------------------------------------------------- transactions
def tx_message(sender, receiver, amount, fee, seq):
    """Canonical bytes that a sender signs. seq is the sender's transaction count, so an
    old signature cannot be replayed."""
    return json.dumps({"from": sender, "to": receiver, "amount": f"{float(amount):.2f}",
                       "fee": f"{float(fee):.2f}", "seq": int(seq)}, sort_keys=True, separators=(",", ":")).encode()


def sign_transaction(private_key_hex, sender, receiver, amount, fee, seq):
    key = ec.derive_private_key(int(private_key_hex, 16), ec.SECP256K1())
    r, s = decode_dss_signature(key.sign(tx_message(sender, receiver, amount, fee, seq), ec.ECDSA(hashes.SHA256())))
    return (r.to_bytes(32, "big") + s.to_bytes(32, "big")).hex()


def verify_signature(public_key_hex, signature_hex, sender, receiver, amount, fee, seq):
    try:
        pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), binascii.unhexlify(public_key_hex))
        raw = binascii.unhexlify(signature_hex)
        sig = encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
        pub.verify(sig, tx_message(sender, receiver, amount, fee, seq), ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
