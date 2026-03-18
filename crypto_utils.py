import hashlib
import binascii
from datetime import date
from ecdsa import SigningKey, SECP256k1, VerifyingKey
from mnemonic import Mnemonic

def generate_wallet():
    """Generates a 12-word seed phrase and corresponding ECDSA keys."""
    mnemo = Mnemonic("english")
    mnemonic_phrase = mnemo.generate(strength=128) # 12 words
    
    # Derive deterministic seed from mnemonic
    seed = mnemo.to_seed(mnemonic_phrase, passphrase="")
    
    # Use first 32 bytes of the seed as the entropy for ECDSA private key
    # (Simplified deterministic generation for this class project)
    private_key = SigningKey.from_string(seed[:32], curve=SECP256k1)
    public_key = private_key.get_verifying_key()
    
    # Return as hex strings along with the mnemonic
    private_hex = private_key.to_string().hex()
    public_hex = public_key.to_string().hex()
    
    return mnemonic_phrase, private_hex, public_hex

def generate_address(public_key_hex):
    """Generates a regular SHA-256 hashed Wallet Address from the public key."""
    sha256_1 = hashlib.sha256(binascii.unhexlify(public_key_hex)).digest()
    sha256_2 = hashlib.sha256(sha256_1).hexdigest()
    return f"0x{sha256_2[:40]}"

def hash_password(date_obj):
    """Hashes a date object to serve as a password."""
    if isinstance(date_obj, date):
        date_str = date_obj.strftime("%Y-%m-%d")
    else:
        date_str = str(date_obj)
    return hashlib.sha256(date_str.encode('utf-8')).hexdigest()

def sign_transaction(private_key_hex, sender, receiver, amount, fee):
    """Signs transaction data with the private key."""
    private_key = SigningKey.from_string(binascii.unhexlify(private_key_hex), curve=SECP256k1)
    message = f"{sender}:{receiver}:{amount}:{fee}".encode('utf-8')
    signature = private_key.sign(message)
    return signature.hex()

def verify_signature(public_key_hex, signature_hex, sender, receiver, amount, fee):
    """Verifies the transaction signature."""
    try:
        public_key = VerifyingKey.from_string(binascii.unhexlify(public_key_hex), curve=SECP256k1)
        message = f"{sender}:{receiver}:{amount}:{fee}".encode('utf-8')
        signature = binascii.unhexlify(signature_hex)
        return public_key.verify(signature, message)
    except Exception as e:
        return False
