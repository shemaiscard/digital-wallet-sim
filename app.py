import os

import pandas as pd
import streamlit as st

import crypto_utils as cu
import ledger as lg

st.set_page_config(page_title="Digital Wallet", page_icon="👛", layout="wide")


@st.cache_resource
def get_store():
    """Firestore when the app has credentials, otherwise a local file for development."""
    try:
        has_cloud = "FIREBASE_KEY" in st.secrets or "firebase" in st.secrets
    except Exception:
        has_cloud = False
    if has_cloud:
        store = lg.firestore_from_secrets(st.secrets)
        store.wipe_legacy()
        return store
    return lg.LocalStore(os.environ.get("WALLET_DB", "wallet_local.json"))


store = get_store()

defaults = {"theme": "Dark", "user": None, "private_key": None, "signup": None, "recovered": None}
for k, v in defaults.items():
    st.session_state.setdefault(k, v)

with open("style.css", "r") as f:
    st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

if st.session_state.theme == "Light":
    st.markdown("""
    <style>
    .glass-card { background: rgba(0,0,0,0.03); border: 1px solid rgba(0,0,0,0.1); color: #111; box-shadow: 0 8px 32px 0 rgba(0,0,0,0.05); }
    .balance-title { color: #555; }
    .balance-amount { background: none; color: #000; -webkit-text-fill-color: initial; }
    .currency-label { color: #1e3c8c; }
    .stTextInput > div > div > input, .stNumberInput > div > div > input { background-color: #fff; color: #000; border: 1px solid #ccc; }
    .stTextInput > div > div > input:focus, .stNumberInput > div > div > input:focus { border-color: #1e3c8c; box-shadow: 0 0 0 1px #1e3c8c; }
    .stButton > button { box-shadow: 0 4px 15px 0 rgba(0,0,0,0.1); }
    [data-testid="stSidebar"] { background-color: #f8f9fa; color: #000; }
    /* Streamlit itself runs on its dark theme (.streamlit/config.toml), so repaint the page, text and widgets too */
    .stApp, [data-testid="stHeader"] { background-color: #fff; }
    .stApp h1, .stApp h2, .stApp h3, .stApp p, .stApp li, .stApp label, [data-testid="stHeader"] button { color: #111; }
    .stApp [data-testid="stCaptionContainer"] { color: #555; }
    .stApp .stButton > button p { color: #fff; }
    .stTextInput [data-baseweb="input"], .stNumberInput [data-baseweb="input"], .stSelectbox [data-baseweb="select"] > div { background-color: #fff; color: #000; border-color: #ccc; }
    .stNumberInput button { background-color: #f1f3f6; color: #111; }
    </style>
    """, unsafe_allow_html=True)


def log_out():
    for k in ("user", "private_key", "signup", "recovered"):
        st.session_state[k] = None


# ---------------------------------------------------------------- sidebar: accounts
with st.sidebar:
    st.title(" Wallet Manager")
    theme_choice = st.radio("Theme", ["Dark", "Light"], index=0 if st.session_state.theme == "Dark" else 1, horizontal=True)
    if theme_choice != st.session_state.theme:
        st.session_state.theme = theme_choice
        st.rerun()
    st.divider()

    if st.session_state.user is None:
        tab_in, tab_up, tab_rec = st.tabs(["Log In", "Sign Up", "Recover"])

        with tab_in:
            username = st.text_input("Username", key="login_user").strip().lower()
            passphrase = st.text_input("Passphrase", type="password", key="login_pass",
                                       help="The words you were given at sign-up, separated by spaces.")
            if st.button("Log In"):
                user = store.get("users", username) if username else None
                if user is None:
                    st.error("Wrong username or passphrase.")
                else:
                    allowed, wait = lg.login_allowed(user)
                    if not allowed:
                        st.error(f"Too many failed attempts. Try again in {wait // 60 + 1} minutes.")
                    else:
                        ok = cu.check_passphrase(user["pw_hash"], passphrase)
                        lg.record_login(store, user, ok)
                        key = cu.decrypt_private_key(user["keystore"], passphrase, username) if ok else None
                        if key:
                            st.session_state.user, st.session_state.private_key = username, key
                            st.rerun()
                        st.error("Wrong username or passphrase.")

        with tab_up:
            new_name = st.text_input("Choose a username", key="signup_user",
                                     help="3 to 20 letters, digits or underscores.").strip().lower()
            if st.button("Create Wallet"):
                if not lg.valid_username(new_name):
                    st.error("Use 3 to 20 letters, digits or underscores.")
                elif store.get("users", new_name):
                    st.error("That username is taken.")
                else:
                    phrase = cu.new_recovery_phrase()
                    st.session_state.signup = {"username": new_name, "phrase": phrase, "passphrase": cu.new_passphrase()}
            s = st.session_state.signup
            if s:
                st.success(f"Wallet ready for **{s['username']}**. Write both down now; they are shown only once.")
                st.markdown("**Login passphrase**")
                st.code(s["passphrase"])
                st.caption(f"{cu.PASSPHRASE_WORDS} random words, about {cu.passphrase_bits():.0f} bits.")
                st.markdown("**Recovery phrase (12 words)**")
                st.code(s["phrase"])
                st.caption("The only way to restore this wallet if you forget the passphrase.")
                typed = st.text_input("Type the passphrase to confirm", type="password", key="signup_confirm")
                if st.button("Register & Log In"):
                    if cu.normalize_passphrase(typed) != s["passphrase"]:
                        st.error("The passphrase does not match.")
                    else:
                        priv, pub = cu.keys_from_phrase(s["phrase"])
                        ok = lg.register(store, s["username"], cu.address_from_public_key(pub), pub,
                                         cu.hash_passphrase(s["passphrase"]),
                                         cu.encrypt_private_key(priv, s["passphrase"], s["username"]))
                        if not ok:
                            st.error("That username was just taken. Choose another.")
                        else:
                            st.session_state.user, st.session_state.private_key = s["username"], priv
                            st.session_state.signup = None
                            st.rerun()

        with tab_rec:
            st.caption("Lost your passphrase? Enter your 12 recovery words to set a new one.")
            words = st.text_area("Recovery phrase", key="rec_words", height=80)
            if st.button("Recover"):
                if not cu.valid_recovery_phrase(words):
                    st.error("That is not a valid 12-word recovery phrase.")
                else:
                    priv, pub = cu.keys_from_phrase(words)
                    user = lg.user_by_public_key(store, pub)
                    if user is None:
                        st.error("No wallet uses this recovery phrase.")
                    else:
                        st.session_state.recovered = {"username": user["username"], "priv": priv,
                                                      "passphrase": cu.new_passphrase()}
            r = st.session_state.recovered
            if r:
                st.success(f"Found **{r['username']}**. Your new passphrase:")
                st.code(r["passphrase"])
                if st.button("Save New Passphrase & Log In"):
                    store.update("users", r["username"], {
                        "pw_hash": cu.hash_passphrase(r["passphrase"]),
                        "keystore": cu.encrypt_private_key(r["priv"], r["passphrase"], r["username"]),
                        "failed": 0, "locked_until": 0.0})
                    st.session_state.user, st.session_state.private_key = r["username"], r["priv"]
                    st.session_state.recovered = None
                    st.rerun()
    else:
        me = store.get("users", st.session_state.user)
        st.success(f"Logged in as: **{me['username']}**")
        st.markdown("**Public Address:**")
        st.code(me["address"])
        if st.button("Log Out"):
            log_out()
            st.rerun()

# ---------------------------------------------------------------- main area
st.title("Digital Wallet System")
st.caption("A simulation for learning. The coins have no value.")

if st.session_state.user is None:
    st.info("Please log in or sign up using the sidebar to access your wallet.")
    st.stop()

me = store.get("users", st.session_state.user)
address = me["address"]
chain = store.all("chain")
bal = lg.balances(chain)

st.markdown(f"""
    <div class="glass-card">
        <div class="balance-title">Current Balance</div>
        <div class="balance-amount">{bal.get(address, 0.0):,.2f} <span class="currency-label">DWC</span></div>
        <div style="font-size: 0.8rem; margin-top: 10px;">Address: {address}</div>
    </div>
""", unsafe_allow_html=True)

left = lg.MINT_LIMIT - lg.mint_count(chain, address)
col_mint, _ = st.columns([1, 4])
with col_mint:
    if left > 0:
        if st.button(f"Free Tokens (Mint: {left} left)"):
            with st.spinner("Mining mint transaction..."):
                ok, msg = lg.add_transaction(store, {"from": "Mint", "to": address, "amount": lg.MINT_AMOUNT,
                                                     "fee": 0.0, "seq": 0, "sig": ""})
            st.rerun() if ok else st.error(msg)
    else:
        st.button("Limit reached (0 left)", disabled=True)

st.divider()
st.subheader("Send Funds")
book = {name: addr for name, addr in lg.directory(store).items() if addr != address}
col1, col2, col3 = st.columns([2, 1, 1])
with col1:
    use_book = st.checkbox("Use Address Book", value=True)
    if use_book and book:
        contact = st.selectbox("Select Recipient", options=sorted(book))
        recipient = book[contact]
        st.caption(f"`{recipient}`")
    elif use_book:
        st.warning("No other users found.")
        recipient = ""
    else:
        recipient = st.text_input("Recipient Address", placeholder="0x...").strip()
with col2:
    amount = st.number_input("Amount", min_value=0.01, step=0.1, format="%.2f")
with col3:
    fee = st.number_input("Network Fee", min_value=0.00, step=0.01, value=0.01, format="%.2f")

if st.button("Mine & Send Transaction"):
    if not recipient:
        st.error("Please enter a recipient address.")
    elif recipient == address:
        st.error("You cannot send funds to yourself.")
    else:
        seq = lg.next_seq(chain, address)
        sig = cu.sign_transaction(st.session_state.private_key, address, recipient, amount, fee, seq)
        with st.spinner("Mining transaction (proof of work)..."):
            ok, msg = lg.add_transaction(store, {"from": address, "to": recipient, "amount": amount,
                                                 "fee": fee, "seq": seq, "sig": sig}, public_key=me["public_key"])
        if ok:
            st.success(f"{msg} Total deducted: {amount + fee:.2f} DWC.")
            st.rerun()
        else:
            st.error(msg)

st.divider()
st.subheader("Transaction History")
if chain:
    rows = [{"block": b["height"], "amount": b["tx"]["amount"], "fee": b["tx"]["fee"], "sender": b["tx"]["from"],
             "receiver": b["tx"]["to"], "nonce": b["nonce"], "hash": b["hash"]} for b in chain]
    df = pd.DataFrame(rows)

    def highlight(row):
        if row["sender"] == address:
            return ["color: #ff5252"] * len(row)
        if row["receiver"] == address:
            return ["color: #00e676"] * len(row)
        return [""] * len(row)

    mine = df[(df["sender"] == address) | (df["receiver"] == address)]
    if not mine.empty:
        st.dataframe(mine.style.apply(highlight, axis=1), width="stretch", hide_index=True)
    else:
        st.info("No transactions found for this wallet yet.")
    with st.expander("View Global Ledger (All Blocks)"):
        st.dataframe(df, width="stretch", hide_index=True)
        if st.button("Verify Ledger"):
            ok, problem = lg.verify_chain(chain)
            st.success(f"All {len(chain)} blocks check out: links, proof of work, signatures and balances.") if ok \
                else st.error(f"Ledger check failed at {problem}.")
    st.caption(f"Network fees collected by miners: {bal.get('Network_Fee', 0.0):.2f} DWC")
else:
    st.info("The ledger is empty. Mint or send some testing funds!")
