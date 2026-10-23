# Simulated Digital Wallet

**Live Demo:** [digital-wallet.streamlit.app](https://digital-wallet.streamlit.app/)

A digital wallet simulation built with Python and Streamlit. It shows how a wallet creates and protects keys, signs transactions and records them on a shared, tamper-evident ledger.

> **Disclaimer:** This is a **simulation for educational purposes only**. No real cryptocurrency or funds are involved, and the coins have no value.

## Features

- **Word passphrase login**: pick a username and receive a passphrase of six random words.
- **Recovery phrase**: a standard 12-word recovery phrase, shown once at sign-up, restores the wallet and sets a new passphrase.
- **Encrypted keys**: your private key is stored only in encrypted form and unlocked with your passphrase.
- **Signed transactions**: every transfer is signed with your key and cannot be replayed.
- **Tamper-evident ledger**: blocks are linked by hashes and mined with a small proof of work; anyone can verify the whole ledger from the app.
- **Free test tokens**: each wallet can mint test coins twice.

## Tech Stack

- **Language**: Python 3
- **UI**: Streamlit
- **Cryptography**: secp256k1 keys, BIP39 and BIP32, Argon2id, AES-GCM
- **Storage**: Firebase Firestore (or a local JSON file when run locally)

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
python -m unittest discover -s tests
```

## Project Structure

- `app.py`: Streamlit interface
- `crypto_utils.py`: keys, passphrases and signatures
- `ledger.py`: accounts, ledger and verification
- `tests/`: unit tests and an end-to-end app test

## Credits

The passphrase words come from the EFF Large Wordlist by the Electronic Frontier Foundation, licensed under CC BY 3.0 US (`eff_large_wordlist.txt`).

## License

MIT License
