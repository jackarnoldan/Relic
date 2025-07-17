https://github.com/users/jackarnoldan/projects/1/views/1
# Relic: Digital Money Without Blockchain

Relics is digital money reborn: 20 million `.rlx` files, each a unique, cryptographically secure unit of value. No blockchain, no miners, no bloat—just raw, unstoppable money that works offline on a USB stick, QR code, or even a toaster. Built in C++ with `libsecp256k1`, Relics is faster than Solana, tougher than Bitcoin, and ready to redefine value .

Join our community to build the future: [MANIFESTO](MANIFESTO.md).

## Why Relics?
- **Scarce**: 20M hard cap, enforced by SHA-256 mint keys and a secure burn list.
- **Offline-First**: Trade via USB or paper, no internet needed.
- **Secure**: ECDSA signatures (secp256k1), SHA-512 hash chains, PBKDF2-encrypted keys.
- **Lean**: 256 KB `.rlx` files, verified locally, no 500 GB blockchain.
- **Private**: Optional burner keys (`--burner`) hide ownership.
- **Open-Source**: Auditable C++ with `nlohmann/json` and comprehensive tests.

## Features
- **Minting**: Create `.rlx` files with secure mint keys.
- **Transferring**: Move ownership with ECDSA-signed hash chains.
- **Verification**: Local validation, no network dependency.
- **Recovery**: Rebuild lost `.rlx` files with private keys.
- **Security**: 256-bit random entropy seed, file locking, 0600 permissions, input sanitization.
- **Tests**: GoogleTest suite covering all functions and edge cases.

## Getting Started
### Prerequisites
- **OpenSSL**: `sudo apt-get install libssl-dev` (Linux), `brew install openssl` (Mac), or [slproweb.com](https://slproweb.com/products/Win32OpenSSL.html) (Windows).
- **libsecp256k1**: `sudo apt-get install libsecp256k1-dev` (Linux), `brew install libsecp256k1` (Mac), or build from [GitHub](https://github.com/bitcoin-core/secp256k1).
- **nlohmann/json**: `sudo apt-get install nlohmann-json3-dev` (Linux), `brew install nlohmann-json` (Mac), or include from [GitHub](https://github.com/nlohmann/json).
- **GoogleTest**: `sudo apt-get install libgtest-dev` (Linux), `brew install gtest` (Mac).
- **Git**: For cloning and pushing.

### Build
```bash
git clone https://github.com/your-username/relic-money.git
cd relic-money
make
