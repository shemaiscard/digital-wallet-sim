# Simulated Digital Wallet

**Live Demo:** [digital-wallet.streamlit.app](https://digital-wallet.streamlit.app/)

A sophisticated digital wallet simulation built with Python and Streamlit. This project demonstrates core blockchain concepts including cryptographic key derivation, transaction signing, and simplified consensus mechanisms.

> **Disclaimer:** This is a **simulation for educational purposes only**. No real cryptocurrency or funds are involved. Generated keys and transactions have no value outside this application.

## Key Features

- **Mnemonic Seed Phrases (BIP39)**: Secure wallet generation using standardized 12-word seed phrases.
- **ECDSA Key Management**: Derivation of SECP256k1 public/private keys from seed phrases.
- **Proof-of-Work (PoW) Simulation**: Simplified mining process for every transaction.
- **Transaction Ecosystem**: Customizable fees and real-time ledger updates.
- **Persistent Storage**: Ledger and wallet state saved via local JSON storage.

## Tech Stack

- **Language**: Python 3.x
- **UI**: Streamlit
- **Cryptography**: ECDSA (SECP256k1)
- **Storage**: JSON

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

## Project Structure

- `app.py` — Streamlit dashboard and UI logic
- `crypto_utils.py` — Key generation and signing functions
- `ledger.py` — Blockchain ledger and transaction validation

## License
MIT License
