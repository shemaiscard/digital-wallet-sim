# Simulated Digital Wallet

A simulated digital wallet application built with Python and Streamlit.

## Features
- **Mnemonic Seed Phrases (BIP39)**: Generate wallets using a 12-word seed phrase.
- **ECDSA Keys**: Derives SECP256k1 public and private keys from the seed phrase.
- **Proof-of-Work (PoW)**: A simplified mining simulation for every transaction before it is appended.
- **Transaction Fees**: Pay a customizable fee on every transaction to the network.
- **Persistent Storage**: Saves the ledger and wallets to local JSON files (`ledger.json`, `wallets.json`).

## Setup and Installation

1. Create a virtual environment and activate it:
```bash
python3 -m venv .venv
source .venv/bin/activate
```

2. Install the required dependencies:
```bash
pip install -r requirements.txt
```

3. Run the Streamlit application:
```bash
streamlit run app.py
```
