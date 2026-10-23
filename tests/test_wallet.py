import copy
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import crypto_utils as cu  # noqa: E402
import ledger as lg  # noqa: E402


class Bip32(unittest.TestCase):
    def test_vector_1(self):
        seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        k, _ = cu.master_key(seed)
        self.assertEqual(k.to_bytes(32, "big").hex(), "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35")
        self.assertEqual(cu.derive_path(seed, "m/0'").to_bytes(32, "big").hex(),
                         "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea")

    def test_phrase_is_deterministic(self):
        p = cu.new_recovery_phrase()
        self.assertTrue(cu.valid_recovery_phrase(p))
        self.assertEqual(cu.keys_from_phrase(p), cu.keys_from_phrase("  " + p.upper() + " "))


class Secrets(unittest.TestCase):
    def test_passphrase(self):
        p = cu.new_passphrase()
        self.assertEqual(len(p.split()), cu.PASSPHRASE_WORDS)
        self.assertAlmostEqual(cu.passphrase_bits(6), 77.55, places=2)
        h = cu.hash_passphrase(p)
        self.assertTrue(h.startswith("$argon2id$"))
        self.assertTrue(cu.check_passphrase(h, p.upper()))
        self.assertFalse(cu.check_passphrase(h, p + " x"))

    def test_keystore(self):
        priv, _ = cu.keys_from_phrase(cu.new_recovery_phrase())
        ks = cu.encrypt_private_key(priv, "alpha beta gamma", "alice")
        self.assertNotIn(priv, str(ks))
        self.assertEqual(cu.decrypt_private_key(ks, "alpha beta gamma", "alice"), priv)
        self.assertIsNone(cu.decrypt_private_key(ks, "alpha beta delta", "alice"))
        self.assertIsNone(cu.decrypt_private_key(ks, "alpha beta gamma", "mallory"))  # bound to the username


class Chain(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        self.tmp.close()
        os.remove(self.tmp.name)
        self.store = lg.LocalStore(self.tmp.name)
        self.a = self.make("alice")
        self.b = self.make("bob")

    def tearDown(self):
        if os.path.exists(self.tmp.name):
            os.remove(self.tmp.name)

    def make(self, name):
        priv, pub = cu.keys_from_phrase(cu.new_recovery_phrase())
        addr = cu.address_from_public_key(pub)
        self.assertTrue(lg.register(self.store, name, addr, pub, cu.hash_passphrase("x y z"),
                                    cu.encrypt_private_key(priv, "x y z", name)))
        return {"priv": priv, "pub": pub, "addr": addr}

    def send(self, frm, to, amount, fee=0.01, seq=None, pub=None):
        chain = self.store.all("chain")
        seq = lg.next_seq(chain, frm["addr"]) if seq is None else seq
        sig = cu.sign_transaction(frm["priv"], frm["addr"], to["addr"], amount, fee, seq)
        return lg.add_transaction(self.store, {"from": frm["addr"], "to": to["addr"], "amount": amount, "fee": fee,
                                               "seq": seq, "sig": sig}, public_key=pub or frm["pub"])

    def mint(self, who):
        return lg.add_transaction(self.store, {"from": "Mint", "to": who["addr"], "amount": 100.0, "fee": 0.0,
                                               "seq": 0, "sig": ""})

    def test_flow_and_verify(self):
        self.assertTrue(self.mint(self.a)[0])
        self.assertTrue(self.send(self.a, self.b, 30)[0])
        bal = lg.balances(self.store.all("chain"))
        self.assertAlmostEqual(bal[self.a["addr"]], 69.99)
        self.assertAlmostEqual(bal[self.b["addr"]], 30.0)
        self.assertEqual(lg.verify_chain(self.store.all("chain")), (True, None))

    def test_rejections(self):
        self.mint(self.a)
        self.mint(self.a)
        self.assertFalse(self.mint(self.a)[0])                       # mint limit
        self.assertFalse(self.send(self.a, self.b, 500)[0])           # overspend
        self.assertTrue(self.send(self.a, self.b, 10)[0])
        self.assertFalse(self.send(self.a, self.b, 10, seq=0)[0])     # replayed sequence number
        self.assertFalse(self.send(self.a, self.b, 10, pub=self.b["pub"])[0])  # key does not own address
        chain = self.store.all("chain")
        tx = dict(chain[-1]["tx"])
        tx["to"] = self.a["addr"]
        self.assertFalse(lg.add_transaction(self.store, {**tx, "seq": 1}, public_key=self.a["pub"])[0])  # sig no longer matches

    def test_tamper_detected(self):
        self.mint(self.a)
        self.send(self.a, self.b, 10)
        self.send(self.a, self.b, 5)
        chain = self.store.all("chain")
        bad = copy.deepcopy(chain)
        bad[1]["tx"]["amount"] = 1.0
        self.assertFalse(lg.verify_chain(bad)[0])
        bad = copy.deepcopy(chain)
        del bad[1]
        self.assertFalse(lg.verify_chain(bad)[0])

    def test_lockout(self):
        user = self.store.get("users", "alice")
        for _ in range(lg.MAX_FAILED_LOGINS):
            lg.record_login(self.store, self.store.get("users", "alice"), False, now=1000.0)
        user = self.store.get("users", "alice")
        self.assertFalse(lg.login_allowed(user, now=1001.0)[0])
        self.assertTrue(lg.login_allowed(user, now=1000.0 + lg.LOCK_SECONDS + 1)[0])


class AppFlow(unittest.TestCase):
    def test_signup_mint_send(self):
        from streamlit.testing.v1 import AppTest
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        db = tempfile.NamedTemporaryFile(suffix=".json", delete=False).name
        os.remove(db)
        os.environ["WALLET_DB"] = db
        cwd = os.getcwd()
        os.chdir(here)
        try:
            at = AppTest.from_file("app.py", default_timeout=60).run()
            for name in ("carol", "dave"):
                at.sidebar.text_input(key="signup_user").set_value(name)
                at.sidebar.button[1].click().run()  # Create Wallet
                passphrase = at.session_state.signup["passphrase"]
                at.sidebar.text_input(key="signup_confirm").set_value(passphrase)
                at.sidebar.button[2].click().run()  # Register & Log In
                self.assertEqual(at.session_state.user, name)
                at.button[0].click().run()          # Free Tokens
                self.assertFalse(at.exception)
                at.sidebar.button[0].click().run()  # Log Out
            store = lg.LocalStore(db)
            self.assertEqual(len(store.all("users")), 2)
            self.assertEqual(len(store.all("chain")), 2)
            self.assertNotIn("phrase", str(store.data["users"]))
            self.assertEqual(lg.verify_chain(store.all("chain")), (True, None))
        finally:
            os.chdir(cwd)
            os.remove(db)


if __name__ == "__main__":
    unittest.main()
