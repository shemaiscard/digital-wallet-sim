import hashlib
import binascii
from datetime import date
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from mnemonic import Mnemonic

# SECP256K1 curve order — used to clamp seed-derived private key to valid range
_CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def _private_key_from_hex(private_key_hex):
    return ec.derive_private_key(int(private_key_hex, 16), ec.SECP256K1(), default_backend())


def _public_key_from_hex(public_key_hex):
    raw = binascii.unhexlify(public_key_hex)  # 64 bytes: x || y
    x = int.from_bytes(raw[:32], "big")
    y = int.from_bytes(raw[32:], "big")
    return ec.EllipticCurvePublicNumbers(x=x, y=y, curve=ec.SECP256K1()).public_key(default_backend())


def generate_wallet():
    """Generates a 12-word seed phrase and corresponding EC keys."""
    mnemo = Mnemonic("english")
    mnemonic_phrase = mnemo.generate(strength=128)
    seed = mnemo.to_seed(mnemonic_phrase, passphrase="")

    # Clamp first 32 seed bytes to a valid SECP256K1 scalar
    private_value = (int.from_bytes(seed[:32], "big") % (_CURVE_ORDER - 1)) + 1
    private_key = ec.derive_private_key(private_value, ec.SECP256K1(), default_backend())
    public_key = private_key.public_key()

    private_hex = private_key.private_numbers().private_value.to_bytes(32, "big").hex()
    pub_nums = public_key.public_numbers()
    public_hex = (pub_nums.x.to_bytes(32, "big") + pub_nums.y.to_bytes(32, "big")).hex()

    return mnemonic_phrase, private_hex, public_hex


def generate_address(public_key_hex):
    """Generates a wallet address from the public key via double SHA-256."""
    sha256_1 = hashlib.sha256(binascii.unhexlify(public_key_hex)).digest()
    sha256_2 = hashlib.sha256(sha256_1).hexdigest()
    return f"0x{sha256_2[:40]}"


def hash_password(date_obj):
    """Hashes a date object to serve as a password."""
    date_str = date_obj.strftime("%Y-%m-%d") if isinstance(date_obj, date) else str(date_obj)
    return hashlib.sha256(date_str.encode("utf-8")).hexdigest()


def sign_transaction(private_key_hex, sender, receiver, amount, fee):
    """Signs transaction data with the private key. Returns a 64-byte raw (r || s) hex signature."""
    private_key = _private_key_from_hex(private_key_hex)
    message = f"{sender}:{receiver}:{amount}:{fee}".encode("utf-8")
    der_sig = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_sig)
    return (r.to_bytes(32, "big") + s.to_bytes(32, "big")).hex()


def verify_signature(public_key_hex, signature_hex, sender, receiver, amount, fee):
    """Verifies a 64-byte raw (r || s) transaction signature."""
    try:
        public_key = _public_key_from_hex(public_key_hex)
        message = f"{sender}:{receiver}:{amount}:{fee}".encode("utf-8")
        raw_sig = binascii.unhexlify(signature_hex)
        r = int.from_bytes(raw_sig[:32], "big")
        s = int.from_bytes(raw_sig[32:], "big")
        der_sig = encode_dss_signature(r, s)
        public_key.verify(der_sig, message, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, Exception):
        return False
