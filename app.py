import streamlit as st
import pandas as pd
from datetime import date
from crypto_utils import generate_wallet, generate_address, sign_transaction, hash_password
from ledger import init_ledger, save_wallets, get_balance, add_transaction

st.set_page_config(page_title="Digital Wallet", page_icon="👛", layout="wide")

# Theme / Init settings
if 'theme' not in st.session_state:
    st.session_state.theme = "Dark"
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
if 'login_step' not in st.session_state:
    st.session_state.login_step = 1
if 'temp_signup_wallet' not in st.session_state:
    st.session_state.temp_signup_wallet = None
if 'login_pending_wallet' not in st.session_state:
    st.session_state.login_pending_wallet = None

init_ledger()

# Load base CSS
with open("style.css", "r") as f:
    st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)
    
if st.session_state.theme == "Light":
    st.markdown("""
    <style>
    /* Injections to override default CSS and make it Light Mode */
    .glass-card { background: rgba(0,0,0,0.03); border: 1px solid rgba(0,0,0,0.1); color: #111; box-shadow: 0 8px 32px 0 rgba(0,0,0,0.05); }
    .balance-title { color: #555; }
    .balance-amount { background: none; color: #000; -webkit-text-fill-color: initial; }
    .currency-label { color: #1e3c8c; }
    .stTextInput > div > div > input, .stNumberInput > div > div > input { background-color: #fff; color: #000; border: 1px solid #ccc; }
    .stTextInput > div > div > input:focus, .stNumberInput > div > div > input:focus { border-color: #1e3c8c; box-shadow: 0 0 0 1px #1e3c8c; }
    .stButton > button { box-shadow: 0 4px 15px 0 rgba(0,0,0,0.1); }
    [data-testid="stSidebar"] { background-color: #f8f9fa; color: #000; }
    </style>
    """, unsafe_allow_html=True)

# Sidebar
with st.sidebar:
    st.title(" Wallet Manager")
    
    # Theme switch
    theme_choice = st.radio("Theme", ["Dark", "Light"], index=0 if st.session_state.theme == "Dark" else 1, horizontal=True)
    if theme_choice != st.session_state.theme:
        st.session_state.theme = theme_choice
        st.rerun()
        
    st.divider()
    
    if not st.session_state.logged_in:
        tabs = st.tabs(["Log In", "Sign Up"])
        
        with tabs[1]:
            st.subheader("Create Account")
            if st.button("Generate New Wallet"):
                mnemonic_phrase, priv, pub = generate_wallet()
                addr = generate_address(pub)
                st.session_state.temp_signup_wallet = {
                    'mnemonic': mnemonic_phrase,
                    'private_key': priv,
                    'public_key': pub,
                    'address': addr,
                    'username': mnemonic_phrase.split()[0],
                    'twelfth_word': mnemonic_phrase.split()[11]
                }
                
            if st.session_state.temp_signup_wallet:
                w = st.session_state.temp_signup_wallet
                st.success("Wallet generated!")
                st.info(f"**Username (1st Word):** {w['username']}\n\n**Verification (12th Word):** {w['twelfth_word']}")
                st.caption("Please write these down. You will need them to log in.")
                
                signup_date = st.date_input("Choose Password (Date)", min_value=date(2024, 1, 1), max_value=date(2026, 12, 31), value=date(2024, 1, 1))
                
                if st.button("Register & Login"):
                    w['password_hash'] = hash_password(signup_date)
                    st.session_state.wallets.append(w)
                    save_wallets()
                    st.session_state.logged_in = True
                    st.session_state.active_wallet_index = len(st.session_state.wallets) - 1
                    st.session_state.temp_signup_wallet = None
                    st.success("Registered successfully!")
                    st.rerun()
                    
        with tabs[0]:
            st.subheader("Sign In")
            if st.session_state.login_step == 1:
                login_user = st.text_input("Username (1st Word)")
                login_date = st.date_input("Password (Date)", min_value=date(2024, 1, 1), max_value=date(2026, 12, 31), value=date(2024, 1, 1))
                
                if st.button("Next"):
                    if not login_user:
                        st.error("Please enter a username.")
                    else:
                        hashed_attempt = hash_password(login_date)
                        found = False
                        for idx, w in enumerate(st.session_state.wallets):
                            if w.get('username') == login_user.lower().strip() and w.get('password_hash') == hashed_attempt:
                                st.session_state.login_pending_wallet = (idx, w)
                                found = True
                                break
                        
                        if found:
                            st.session_state.login_step = 2
                            st.rerun()
                        else:
                            st.error("Invalid Username or Password.")
                            
            elif st.session_state.login_step == 2:
                st.info("Username and Password correct. Proceed to verify.")
                verif_word = st.text_input("Verification (12th Word)", type="password")
                
                col1, col2 = st.columns(2)
                with col1:
                    if st.button("Back"):
                        st.session_state.login_step = 1
                        st.session_state.login_pending_wallet = None
                        st.rerun()
                with col2:
                    if st.button("Verify & Login"):
                        idx, w = st.session_state.login_pending_wallet
                        if verif_word.lower().strip() == w.get('twelfth_word'):
                            st.session_state.logged_in = True
                            st.session_state.active_wallet_index = idx
                            st.session_state.login_step = 1
                            st.session_state.login_pending_wallet = None
                            st.success("Logged in successfully!")
                            st.rerun()
                        else:
                            st.error("Incorrect verification word.")

    else:
        # Logged In
        active_wallet = st.session_state.wallets[st.session_state.active_wallet_index]
        st.success(f"Logged in as: **{active_wallet.get('username', 'Unknown')}**")
        st.markdown("**Public Address:**")
        st.code(active_wallet['address'])
        
        with st.expander("Show Security Details ⚠️"):
            st.warning("Never share your private key or seed phrase!")
            if 'mnemonic' in active_wallet:
                st.markdown("**Seed Phrase (12 Words):**")
                st.code(active_wallet['mnemonic'])
            if 'private_key' in active_wallet:
                st.markdown("**Private Key:**")
                st.code(active_wallet['private_key'])
        
        if st.button("Log Out"):
            st.session_state.logged_in = False
            st.session_state.login_step = 1
            st.session_state.login_pending_wallet = None
            st.rerun()

# Main UI
st.title("Digital Wallet System")

if not st.session_state.logged_in:
    st.info("Please log in or sign up using the sidebar to access your wallet.")
else:
    active_wallet = st.session_state.wallets[st.session_state.active_wallet_index]
    wallet_address = active_wallet['address']
    
    # Main UI - Top: Balance Card
    balance = get_balance(wallet_address)
    
    st.markdown(f"""
        <div class="glass-card">
            <div class="balance-title">Current Balance</div>
            <div class="balance-amount">{balance:,.2f} <span class="currency-label">DWC</span></div>
            <div style="font-size: 0.8rem; margin-top: 10px;">
                Address: {wallet_address}
            </div>
        </div>
    """, unsafe_allow_html=True)
    
    # Check Mint constraints: maximum 2 times
    mint_count = sum(1 for tx in st.session_state.ledger if tx['sender'] == "Mint" and tx['receiver'] == wallet_address)
    
    col_mint, _ = st.columns([1, 4])
    with col_mint:
        if mint_count < 2:
            if st.button(f"Free Tokens (Mint: {2 - mint_count} left)"):
                with st.spinner("Mining Mint Transaction..."):
                    add_transaction("Mint", wallet_address, 100.0, 0.0, "mint_signature", "mint_pubkey")
                st.rerun()
        else:
            st.button("Limit reached (0 left)", disabled=True)

    st.divider()
    
    # Main UI - Middle: Send Funds Form
    st.subheader("Send Funds")
    
    address_book = {w.get('username', 'Unknown'): w['address'] for w in st.session_state.wallets if w['address'] != wallet_address}
    
    col1, col2, col3 = st.columns([2, 1, 1])
    with col1:
        use_address_book = st.checkbox("Use Address Book", value=True)
        if use_address_book and address_book:
            contact_name = st.selectbox("Select Recipient", options=list(address_book.keys()))
            recipient = address_book[contact_name]
            st.caption(f"`{recipient}`")
        elif use_address_book and not address_book:
            st.warning("No other users found.")
            recipient = ""
        else:
            recipient = st.text_input("Recipient Address", placeholder="0x...")
            
    with col2:
        amount = st.number_input("Amount", min_value=0.01, step=0.1, format="%.2f")
    with col3:
        fee = st.number_input("Network Fee", min_value=0.00, step=0.01, value=0.01, format="%.2f")
        
    if st.button("Mine & Send Transaction"):
        if not recipient:
            st.error("Please enter a recipient address.")
        elif recipient == wallet_address:
            st.error("You cannot send funds to yourself.")
        else:
            signature = sign_transaction(
                active_wallet['private_key'], 
                wallet_address, 
                recipient, 
                amount,
                fee
            )
            
            with st.spinner(" Mining transaction (Calculating PoW)..."):
                success, msg = add_transaction(
                    wallet_address,
                    recipient,
                    amount,
                    fee,
                    signature,
                    active_wallet['public_key']
                )
            
            if success:
                st.success(f"{msg} (Total deducted: {amount + fee:.2f} DWC)")
                st.rerun()
            else:
                st.error(msg)
                
    st.divider()
    
    # Main UI - Bottom: Transaction History
    st.subheader("Transaction History ")
    
    if st.session_state.ledger:
        df = pd.DataFrame(st.session_state.ledger)
        
        def highlight_tx(row):
            if row['sender'] == wallet_address:
                return ['color: #ff5252'] * len(row)
            elif row['receiver'] == wallet_address:
                return ['color: #00e676'] * len(row)
            return [''] * len(row)
            
        base_cols = ['status', 'amount', 'fee', 'sender', 'receiver', 'nonce', 'hash']
        # Handing missing keys if older transactions exist
        for col in base_cols:
            if col not in df.columns:
                df[col] = None
        df = df[base_cols]
        
        user_txs = df[(df['sender'] == wallet_address) | (df['receiver'] == wallet_address)]
        
        if not user_txs.empty:
            styled_df = user_txs.style.apply(highlight_tx, axis=1)
            st.dataframe(styled_df, use_container_width=True, hide_index=True)
        else:
            st.info("No transactions found for this wallet yet.")
            
        with st.expander("View Global Ledger (All Transactions)"):
            st.dataframe(df, use_container_width=True, hide_index=True)
            
        network_fees = get_balance("Network_Fee")
        st.caption(f"Network Fees Collected By Miners: {network_fees:.2f} DWC")
    else:
        st.info("The ledger is empty. Mint or send some testing funds!")
