#!/usr/bin/env python3
"""Measurements for the wallet paper, on this machine's CPU.

  python bench/security_bench.py --out cpu_results.json

- login cost: one Argon2id check with the app's parameters (time_cost=3, 64 MiB, 1 lane)
- guessing rates on one CPU core: unsalted SHA-256 of a date string (the first
  version's password hash) and Argon2id with the app's parameters
- the first version's whole password space: hash all 1,096 dates
- mining: time and nonces to mine one block at the app's difficulty
- ledger verification time and tamper detection on generated chains
"""
import argparse
import copy
import datetime
import hashlib
import json
import os
import platform
import random
import statistics as st
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import crypto_utils as cu  # noqa: E402
import ledger as lg  # noqa: E402


def summ(xs):
    xs = sorted(xs)
    return {"n": len(xs), "median": xs[len(xs) // 2], "mean": st.mean(xs), "sd": st.stdev(xs) if len(xs) > 1 else 0.0,
            "p95": xs[int(0.95 * (len(xs) - 1))], "min": xs[0], "max": xs[-1]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--chains", default="10,100,1000")
    args = ap.parse_args()
    out = {"python": platform.python_version(), "machine": platform.machine(), "platform": platform.platform(),
           "cpu": next((l.split(":", 1)[1].strip() for l in open("/proc/cpuinfo") if l.startswith("model name")), "?"),
           "argon2": cu.ARGON2, "passphrase_words": cu.PASSPHRASE_WORDS, "wordlist": len(cu.WORDLIST)}

    # login cost and the Argon2id guessing rate on one core
    h = cu.hash_passphrase(cu.new_passphrase())
    t = []
    for _ in range(30):
        t0 = time.perf_counter()
        cu.check_passphrase(h, "wrong guess words here now")
        t.append(time.perf_counter() - t0)
    out["argon2id_verify_s"] = summ(t)
    out["argon2id_guesses_per_s_one_core"] = 1 / out["argon2id_verify_s"]["median"]
    t0 = time.perf_counter()
    ks = cu.encrypt_private_key("11" * 32, "a b c d e f", "user")
    out["keystore_encrypt_s"] = time.perf_counter() - t0
    t0 = time.perf_counter()
    cu.decrypt_private_key(ks, "a b c d e f", "user")
    out["keystore_decrypt_s"] = time.perf_counter() - t0

    # the first version: unsalted SHA-256 of a YYYY-MM-DD date between 2024-01-01 and 2026-12-31
    dates = [(datetime.date(2024, 1, 1) + datetime.timedelta(days=i)).strftime("%Y-%m-%d") for i in range(1096)]
    n = 2_000_000
    msgs = [b"2025-06-15"] * 1
    t0 = time.perf_counter()
    for i in range(n):
        hashlib.sha256(msgs[0]).digest()
    sha_rate = n / (time.perf_counter() - t0)
    out["sha256_guesses_per_s_one_core"] = sha_rate
    t0 = time.perf_counter()
    table = {hashlib.sha256(d.encode()).hexdigest(): d for d in dates}
    out["v1_full_password_table_s"] = time.perf_counter() - t0
    out["v1_password_space"] = len(table)

    # mining at the app's difficulty
    rnd = random.Random(1)
    mine_t, nonces = [], []
    for i in range(200):
        tx = {"from": "a", "to": "b", "amount": 1.0, "fee": 0.01, "seq": i, "sig": f"{rnd.getrandbits(256):064x}"}
        t0 = time.perf_counter()
        nonce, _ = lg.mine(i, "0" * 64, tx)
        mine_t.append(time.perf_counter() - t0)
        nonces.append(nonce + 1)
    out["mine_s"] = summ(mine_t)
    out["mine_attempts"] = summ(nonces)
    out["mine_expected_attempts"] = 16 ** lg.DIFFICULTY

    # ledger verification and tamper detection
    out["chains"] = {}
    for size in [int(x) for x in args.chains.split(",")]:
        path = tempfile.NamedTemporaryFile(suffix=".json", delete=False).name
        os.remove(path)
        store = lg.LocalStore(path)
        users = []
        for j in range(5):
            priv, pub = cu.keys_from_phrase(cu.new_recovery_phrase())
            users.append((priv, pub, cu.address_from_public_key(pub)))
        for _, _, addr in users:
            for _ in range(2):
                lg.add_transaction(store, {"from": "Mint", "to": addr, "amount": 100.0, "fee": 0.0, "seq": 0, "sig": ""})
        chain = store.all("chain")
        while len(chain) < size:
            a, b = rnd.sample(users, 2)
            seq = lg.next_seq(chain, a[2])
            sig = cu.sign_transaction(a[0], a[2], b[2], 0.05, 0.0, seq)
            ok, _ = lg.add_transaction(store, {"from": a[2], "to": b[2], "amount": 0.05, "fee": 0.0, "seq": seq, "sig": sig},
                                       public_key=a[1])
            chain = store.all("chain")
        t = []
        for _ in range(5):
            t0 = time.perf_counter()
            ok, problem = lg.verify_chain(chain)
            t.append(time.perf_counter() - t0)
        # tampering: change one amount, one receiver, drop a block, swap two blocks, forge a re-mined block
        tamper = {"amount": 0, "receiver": 0, "deleted_block": 0, "swapped_blocks": 0, "remined_block": 0,
                  "remined_suffix_signed": 0, "remined_suffix_mint": 0}
        trials = 20
        for _ in range(trials):
            i = rnd.randrange(1, len(chain) - 1)
            c = copy.deepcopy(chain); c[i]["tx"]["amount"] += 1.0
            tamper["amount"] += not lg.verify_chain(c)[0]
            c = copy.deepcopy(chain); c[i]["tx"]["to"] = users[0][2] if c[i]["tx"]["to"] != users[0][2] else users[1][2]
            tamper["receiver"] += not lg.verify_chain(c)[0]
            c = copy.deepcopy(chain); del c[i]
            tamper["deleted_block"] += not lg.verify_chain(c)[0]
            c = copy.deepcopy(chain); c[i], c[i + 1] = c[i + 1], c[i]
            tamper["swapped_blocks"] += not lg.verify_chain(c)[0]
            # an attacker who re-mines the edited block (and does not redo the rest)
            c = copy.deepcopy(chain); c[i]["tx"]["amount"] += 1.0
            c[i]["nonce"], c[i]["hash"] = lg.mine(c[i]["height"], c[i]["prev"], c[i]["tx"])
            tamper["remined_block"] += not lg.verify_chain(c)[0]
            # an attacker with write access who edits a block and re-mines every block after it
            for kind, pick in (("remined_suffix_signed", lambda b: b["tx"]["from"] != "Mint"),
                               ("remined_suffix_mint", lambda b: b["tx"]["from"] == "Mint")):
                idx = [k for k, b in enumerate(chain) if pick(b)]
                j = rnd.choice(idx)
                c = copy.deepcopy(chain)
                c[j]["tx"]["amount"] += 1.0
                prev = c[j - 1]["hash"] if j else lg.GENESIS_HASH
                for k in range(j, len(c)):
                    c[k]["prev"] = prev
                    c[k]["nonce"], c[k]["hash"] = lg.mine(c[k]["height"], prev, c[k]["tx"])
                    prev = c[k]["hash"]
                tamper[kind] += not lg.verify_chain(c)[0]
        out["chains"][size] = {"verified": ok, "verify_s": summ(t), "tamper_trials": trials, "tamper_detected": tamper}
        os.remove(path)
    with open(args.out, "w") as f:
        json.dump(out, f, indent=2)
    print(json.dumps({k: v for k, v in out.items() if k != "chains"}, indent=1, default=str)[:3000])
    print(json.dumps(out["chains"], indent=1)[:2000])


if __name__ == "__main__":
    main()
