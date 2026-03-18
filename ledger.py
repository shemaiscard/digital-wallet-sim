import streamlit as st
import hashlib
import json # Added import for json
import firebase_admin
from firebase_admin import credentials, firestore
from crypto_utils import verify_signature

# Initialize Firebase exactly once per application lifespan
if not firebase_admin._apps:
    try:
        import tempfile
        
        if 'FIREBASE_KEY' in st.secrets:
            # Handle Raw JSON string (or accidentally parsed dict)
            raw_content = st.secrets['FIREBASE_KEY']
            if type(raw_content) is dict or "AttrDict" in str(type(raw_content)):
                 raw_content = json.dumps(dict(raw_content))
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp:
                temp.write(str(raw_content))
                temp_path = temp.name
            cred = credentials.Certificate(temp_path)
            
        elif 'firebase' in st.secrets:
            # Handle standard Streamlit TOML Dictionary
            cred_dict = dict(st.secrets['firebase'])
            if 'private_key' in cred_dict:
                cred_dict['private_key'] = cred_dict['private_key'].replace('\\n', '\n')
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp:
                json.dump(cred_dict, temp)
                temp_path = temp.name
            cred = credentials.Certificate(temp_path)
            
        else:
            cred = credentials.Certificate('firebase_key.json')
            
        firebase_admin.initialize_app(cred)
    except Exception as e:
        st.error(f"Error initializing Firebase: {e}")
        st.stop()
db = firestore.client()

def init_ledger():
    """Initializes the simulated ledger and wallets directly from Firestore."""
    if 'ledger' not in st.session_state:
        # Load from Firebase "ledger" collection
        docs = db.collection('ledger').stream()
        st.session_state.ledger = [doc.to_dict() for doc in docs]
            
    if 'wallets' not in st.session_state:
        # Load from Firebase "wallets" collection
        docs = db.collection('wallets').stream()
        st.session_state.wallets = [doc.to_dict() for doc in docs]

def save_ledger(tx=None):
    """Saves a single transaction to Firebase Firestore."""
    if tx:
        db.collection('ledger').document(tx['hash']).set(tx)
    else:
        # Fallback if no specific tx provided, bulk upload all
        for t in st.session_state.ledger:
            db.collection('ledger').document(t['hash']).set(t)

def save_wallets():
    """Saves wallets securely to Firebase using the wallet address as document ID."""
    for w in st.session_state.wallets:
        db.collection('wallets').document(w['address']).set(w)

def get_balance(address):
    """Calculates balance by iterating through the session ledger."""
    balance = 0.0
    for tx in st.session_state.ledger:
        if tx['receiver'] == address:
            balance += float(tx['amount'])
            
        # Deduct amount and fee from sender
        if tx['sender'] == address:
            balance -= float(tx['amount']) + float(tx.get('fee', 0.0))
            
        # Give fees to Network_Fee address if checked
        if address == "Network_Fee" and 'fee' in tx:
            balance += float(tx['fee'])
            
    return balance

def mine_transaction(tx_string, difficulty=3):
    """Simple Proof-of-Work: finds a nonce where hash starts with `difficulty` zeros."""
    nonce = 0
    target = "0" * difficulty
    
    while True:
        record = f"{tx_string}:{nonce}".encode('utf-8')
        block_hash = hashlib.sha256(record).hexdigest()
        if block_hash.startswith(target):
            return nonce, block_hash
        nonce += 1

def add_transaction(sender_address, receiver_address, amount, fee, signature, public_key):
    """Validates, mines, and appends a new transaction to the global Firestore ledger."""
    amount = float(amount)
    fee = float(fee)
    
    if amount <= 0:
        return False, "Amount must be greater than zero."
        
    if sender_address == receiver_address:
         return False, "Cannot send to the same address."

    current_balance = get_balance(sender_address)

    # Verify signature ("Mint" sender skips signature for demo purposes)
    if sender_address != "Mint":
        if not verify_signature(public_key, signature, sender_address, receiver_address, amount, fee):
            return False, "Invalid signature!"
        
        # Check balance against amount + fee
        if current_balance < (amount + fee):
            return False, f"Insufficient balance! You need {amount + fee} but have {current_balance}."

    tx_string = f"{sender_address}:{receiver_address}:{amount}:{fee}:{signature}"
    nonce, block_hash = mine_transaction(tx_string, difficulty=3)

    # Create transaction record
    tx = {
        'sender': sender_address,
        'receiver': receiver_address,
        'amount': amount,
        'fee': fee,
        'signature': signature,
        'nonce': nonce,
        'hash': block_hash,
        'status': 'Confirmed'
    }
    
    # Append to local ledger state
    st.session_state.ledger.append(tx)
    # Push the single document to Firestore to instantly sync with all other users
    save_ledger(tx)
    return True, "Transaction successfully mined and appended to the Cloud!"
