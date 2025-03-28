# Bitack - A Simple Bitcoin Signet Wallet

**Bitack** is a simple Bitcoin Signet Wallet. It serves as a lightweight wallet that allows users to generate Bitcoin transactions, sign them, and interact with the signet network. It is built with a focus on understanding Bitcoin transactions, wallets, and the underlying mechanisms of the Bitcoin protocol.

## Features

- **Bitcoin Signet Network Support**: Connect to the Bitcoin signet network using Bitcoin Core for testing purposes.
- **Transaction Signing**: Sign transactions with a private key.
- **Base58 Encoding/Decoding**: Support Base58check encoding/decoding for creating Bitcoin addresses from public keys.
- **Hierarchical Deterministic (HD) Wallet Key Generation**: Uses HD to generate public and private child keys.
- **Lightweight Design**: Minimal, easy-to-understand codebase for educational purposes.
- **Implemented Bip143 Transaction Digest Algorithm**: Supports the BIP143 signature hashing algorithm for transaction signing.
- **Support P2WPKH, P2WSH multisig transactions**: Implements Pay-to-Witness-PubKey-Hash and Pay-to-Witness-Script-Hash transactions.

## Installation

To get started with Bitack, follow these steps:

1. Clone the repository and navigate to the project directory:

   ```bash
   git clone https://github.com/yourusername/bitack.git
   cd bitack
   ```

2. Install Bitcoin Core and set up a Signet server. You can follow the [official Bitcoin documentation](https://bitcoin.org/en/full-node) for setting up Bitcoin Core with the Signet network.

3. Install the required Python dependencies:

   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. Start Bitcoin Core in Signet mode and ensure the server is running.

2. Run the wallet script to generate Bitcoin addresses, sign transactions, or interact with the Signet network.

   Example:

   ```bash
   python balance.py
   python spend.py
   ```
