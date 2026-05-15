# Simulated Digital Wallet

A sophisticated digital wallet simulation application built with Python and Streamlit. This project demonstrates core blockchain concepts, including cryptographic key derivation, transaction signing, and simplified consensus mechanisms.

## Key Features

- **Mnemonic Seed Phrases (BIP39)**: Secure wallet generation using standardized 12-word seed phrases.
- **ECDSA Key Management**: Derivation of SECP256k1 public and private keys from seed phrases for secure identity.
- **Proof-of-Work (PoW) Simulation**: A simplified mining process required for every transaction to validate and append to the ledger.
- **Transaction Ecosystem**: Support for customizable transaction fees and real-time ledger updates.
- **Persistent Storage**: Robust data persistence for the ledger and wallet states using local JSON storage.

## Technical Stack

- **Language**: Python 3.x
- **UI Framework**: Streamlit
- **Cryptography**: ECDSA (SECP256k1)
- **Data Format**: JSON

## Setup and Installation

### 1. Environment Configuration

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 2. Dependency Installation

Install the required Python packages:

```bash
pip install -r requirements.txt
```

### 3. Application Execution

Launch the Streamlit dashboard:

```bash
streamlit run app.py
```

## Project Structure

- **app.py**: The main Streamlit dashboard and user interface logic.
- **crypto_utils.py**: Cryptographic functions for key generation and signing.
- **ledger.py**: Logic for managing the blockchain ledger and transaction validation.

## License

This project is licensed under the MIT License.
