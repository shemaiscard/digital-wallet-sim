"""Accounts and the hash-linked ledger, stored in Firestore (or a local JSON file).

Collections
  users   one document per username: address, public key, Argon2id passphrase hash,
          encrypted private key, failed-login counter and lock time. No recovery
          phrase and no plaintext key is ever stored.
  chain   one document per block, id = zero-padded height. Each block holds one
          transaction, the previous block's hash and a proof-of-work nonce.
"""
import hashlib
import json
import os
import tempfile
import time

from crypto_utils import address_from_public_key, verify_signature

DIFFICULTY = 3            # leading hex zeros in a block hash
MAX_FAILED_LOGINS = 5
LOCK_SECONDS = 15 * 60
MINT_LIMIT = 2
MINT_AMOUNT = 100.0
GENESIS_HASH = "0" * 64
SYSTEM_SENDERS = {"Mint"}


# ---------------------------------------------------------------- storage back ends
class LocalStore:
    """A JSON file, for local runs and tests."""

    def __init__(self, path):
        self.path = path
        self.data = {"users": {}, "chain": {}}
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                self.data = json.load(f)

    def _save(self):
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self.data, f)

    def get(self, col, doc_id):
        return self.data[col].get(doc_id)

    def all(self, col):
        return [self.data[col][k] for k in sorted(self.data[col])]

    def create(self, col, doc_id, doc):
        """Write only if the document does not exist yet. Returns False if it does."""
        if doc_id in self.data[col]:
            return False
        self.data[col][doc_id] = doc
        self._save()
        return True

    def update(self, col, doc_id, fields):
        self.data[col][doc_id].update(fields)
        self._save()


class FirestoreStore:
    def __init__(self, client):
        self.db = client

    def get(self, col, doc_id):
        snap = self.db.collection(col).document(doc_id).get()
        return snap.to_dict() if snap.exists else None

    def all(self, col):
        docs = sorted(self.db.collection(col).stream(), key=lambda d: d.id)
        return [d.to_dict() for d in docs]

    def create(self, col, doc_id, doc):
        from google.api_core.exceptions import AlreadyExists
        try:
            self.db.collection(col).document(doc_id).create(doc)
            return True
        except AlreadyExists:
            return False

    def update(self, col, doc_id, fields):
        self.db.collection(col).document(doc_id).update(fields)

    def wipe_legacy(self):
        """Delete the collections of the first version, which held plaintext recovery
        phrases and private keys. Runs until they are empty; harmless afterwards."""
        removed = 0
        for col in ("wallets", "ledger"):
            for snap in self.db.collection(col).stream():
                snap.reference.delete()
                removed += 1
        return removed


def firestore_from_secrets(secrets):
    import firebase_admin
    from firebase_admin import credentials, firestore
    if not firebase_admin._apps:
        if "FIREBASE_KEY" in secrets:
            raw = secrets["FIREBASE_KEY"]
            info = dict(raw) if not isinstance(raw, str) else json.loads(raw)
        else:
            info = dict(secrets["firebase"])
        if "private_key" in info:
            info["private_key"] = info["private_key"].replace("\\n", "\n")
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(info, f)
            path = f.name
        firebase_admin.initialize_app(credentials.Certificate(path))
        os.remove(path)
    return FirestoreStore(firestore.client())


# ---------------------------------------------------------------- accounts
def valid_username(name):
    return 3 <= len(name) <= 20 and all(c.isascii() and (c.isalnum() or c == "_") for c in name)


def register(store, username, address, public_key, pw_hash, keystore):
    doc = {"username": username, "address": address, "public_key": public_key, "pw_hash": pw_hash,
           "keystore": keystore, "created": time.time(), "failed": 0, "locked_until": 0.0}
    return store.create("users", username, doc)


def login_allowed(user, now=None):
    """Returns (allowed, seconds left on the lock)."""
    now = now or time.time()
    left = user.get("locked_until", 0.0) - now
    return (left <= 0, max(0, int(left)))


def record_login(store, user, ok, now=None):
    now = now or time.time()
    if ok:
        store.update("users", user["username"], {"failed": 0, "locked_until": 0.0})
        return
    failed = user.get("failed", 0) + 1
    fields = {"failed": failed}
    if failed >= MAX_FAILED_LOGINS:
        fields = {"failed": 0, "locked_until": now + LOCK_SECONDS}
    store.update("users", user["username"], fields)


def user_by_public_key(store, public_key):
    return next((u for u in store.all("users") if u["public_key"] == public_key), None)


def directory(store):
    """Public address book: username -> address. Nothing secret leaves the store."""
    return {u["username"]: u["address"] for u in store.all("users")}


# ---------------------------------------------------------------- chain
def block_hash(height, prev_hash, tx, nonce):
    body = json.dumps({"h": height, "prev": prev_hash, "tx": tx, "nonce": nonce}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(body.encode()).hexdigest()


def mine(height, prev_hash, tx, difficulty=DIFFICULTY):
    target = "0" * difficulty
    nonce = 0
    while True:
        h = block_hash(height, prev_hash, tx, nonce)
        if h.startswith(target):
            return nonce, h
        nonce += 1


def balances(chain):
    bal = {}
    for b in chain:
        tx = b["tx"]
        bal[tx["to"]] = bal.get(tx["to"], 0.0) + tx["amount"]
        if tx["from"] not in SYSTEM_SENDERS:
            bal[tx["from"]] = bal.get(tx["from"], 0.0) - tx["amount"] - tx["fee"]
        if tx["fee"]:
            bal["Network_Fee"] = bal.get("Network_Fee", 0.0) + tx["fee"]
    return bal


def next_seq(chain, sender):
    return sum(1 for b in chain if b["tx"]["from"] == sender)


def mint_count(chain, address):
    return sum(1 for b in chain if b["tx"]["from"] == "Mint" and b["tx"]["to"] == address)


def add_transaction(store, tx, public_key=None, retries=5):
    """Validate a transaction, mine it into the next block and store it.

    tx = {"from", "to", "amount", "fee", "seq", "sig"}. Returns (ok, message)."""
    for _ in range(retries):
        chain = store.all("chain")
        amount, fee = round(float(tx["amount"]), 2), round(float(tx["fee"]), 2)
        if amount <= 0 or fee < 0:
            return False, "Amount must be greater than zero and the fee cannot be negative."
        if tx["from"] == tx["to"]:
            return False, "Cannot send to the same address."
        if tx["from"] == "Mint":
            if mint_count(chain, tx["to"]) >= MINT_LIMIT:
                return False, "This wallet has used its free tokens."
        else:
            if not public_key or address_from_public_key(public_key) != tx["from"]:
                return False, "This key does not own the sending address."
            if tx["seq"] != next_seq(chain, tx["from"]):
                return False, "Stale or replayed transaction; please try again."
            if not verify_signature(public_key, tx["sig"], tx["from"], tx["to"], amount, fee, tx["seq"]):
                return False, "Invalid signature."
            have = balances(chain).get(tx["from"], 0.0)
            if have + 1e-9 < amount + fee:
                return False, f"Insufficient balance: you need {amount + fee:.2f} but have {have:.2f}."
        height = len(chain)
        prev = chain[-1]["hash"] if chain else GENESIS_HASH
        body = {"from": tx["from"], "to": tx["to"], "amount": amount, "fee": fee, "seq": tx["seq"],
                "sig": tx["sig"], "pub": public_key}
        nonce, h = mine(height, prev, body)
        block = {"height": height, "prev": prev, "tx": body, "nonce": nonce, "hash": h, "time": time.time()}
        if store.create("chain", f"{height:08d}", block):
            return True, f"Confirmed in block {height}."
        # another user took this height first; recompute against the new tip
    return False, "The ledger was busy; please try again."


def verify_chain(chain, difficulty=DIFFICULTY):
    """Recheck every link, hash, proof of work, signature, sequence number and balance.
    Returns (ok, first problem or None)."""
    prev = GENESIS_HASH
    seen = {}
    bal = {}
    mints = {}
    for i, b in enumerate(chain):
        tx = b["tx"]
        if b["height"] != i or b["prev"] != prev:
            return False, f"block {i}: broken link"
        if block_hash(b["height"], b["prev"], tx, b["nonce"]) != b["hash"] or not b["hash"].startswith("0" * difficulty):
            return False, f"block {i}: hash or proof of work does not match"
        if tx["from"] == "Mint":
            mints[tx["to"]] = mints.get(tx["to"], 0) + 1
            if tx["amount"] != MINT_AMOUNT or tx["fee"] != 0:
                return False, f"block {i}: mint amount altered"
            if mints[tx["to"]] > MINT_LIMIT:
                return False, f"block {i}: mint limit exceeded"
        else:
            if tx["seq"] != seen.get(tx["from"], 0):
                return False, f"block {i}: sequence number out of order"
            if not verify_signature(tx["pub"], tx["sig"], tx["from"], tx["to"], tx["amount"], tx["fee"], tx["seq"]):
                return False, f"block {i}: bad signature"
            if address_from_public_key(tx["pub"]) != tx["from"]:
                return False, f"block {i}: key does not own the sending address"
            if bal.get(tx["from"], 0.0) + 1e-9 < tx["amount"] + tx["fee"]:
                return False, f"block {i}: overspend"
            seen[tx["from"]] = seen.get(tx["from"], 0) + 1
            bal[tx["from"]] = bal.get(tx["from"], 0.0) - tx["amount"] - tx["fee"]
        bal[tx["to"]] = bal.get(tx["to"], 0.0) + tx["amount"]
        prev = b["hash"]
    return True, None
