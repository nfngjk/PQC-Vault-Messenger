# PQC-Vault-Messenger

A post-quantum cryptography tool built in C++ using [liboqs](https://github.com/open-quantum-safe/liboqs).

Implements two core features:
- **Vault**: Encrypt and decrypt files using Kyber768 + Dilithium3 + AES-256-GCM
- **Messenger**: End-to-end encrypted chat using Kyber768 handshake + AES-256-GCM

## Cryptographic Algorithms

| Purpose | Algorithm | Standard |
|---------|-----------|----------|
| Key Encapsulation (KEM) | CRYSTALS-Kyber768 | NIST FIPS 203 |
| Digital Signature | CRYSTALS-Dilithium3 | NIST FIPS 204 |
| Symmetric Encryption | AES-256-GCM | NIST |

## Build

### Prerequisites
- MSYS2 UCRT64
- CMake
- Ninja
- GCC/G++
- OpenSSL

### Install dependencies (MSYS2 UCRT64)

```bash
pacman -S mingw-w64-ucrt-x86_64-cmake
pacman -S mingw-w64-ucrt-x86_64-ninja
pacman -S mingw-w64-ucrt-x86_64-openssl
```

### Build

```bash
git clone --recurse-submodules https://github.com/<your-username>/PQC-Vault-Messenger
cd PQC-Vault-Messenger
cmake -B build -G Ninja -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++
cmake --build build
```

## Usage

### Vault — File Encryption

```bash
# Generate keypair
./build/PQC_Project.exe keygen mykey

# Encrypt a file
./build/PQC_Project.exe encrypt secret.txt secret.pqc mykey

# Decrypt a file
./build/PQC_Project.exe decrypt secret.pqc recovered.txt mykey
```

### Messenger — Encrypted Chat

```bash
# Start server (Terminal 1)
./build/PQC_Project.exe listen 9999

# Connect as client (Terminal 2)
./build/PQC_Project.exe connect 127.0.0.1 9999
```

Type messages and press Enter to send. Type `/quit` to exit.

## How It Works

### Vault

```
1. Generate Kyber768 keypair
2. Encapsulate → shared secret
3. Use shared secret as AES-256-GCM key
4. Encrypt file content
5. Sign with Dilithium3
6. Pack into .pqc file format
```

### Messenger

```
Client                        Server
  |                              |
  | <---- Kyber public key ----- |
  |                              |
  | ----- KEM ciphertext ------> |
  |                              |
  |   (both derive shared key)   |
  |                              |
  | <== AES-256-GCM messages ==> |
```

## Project Structure

```
PQC-Vault-Messenger/
├── src/
│   ├── core/
│   │   ├── kyber.hpp/cpp       # Kyber KEM wrapper
│   │   ├── dilithium.hpp/cpp   # Dilithium signature wrapper
│   │   └── aes_gcm.hpp/cpp     # AES-256-GCM wrapper
│   ├── vault/
│   │   ├── vault.hpp/cpp       # File encrypt/decrypt logic
│   │   └── pqc_format.hpp/cpp  # .pqc file format
│   ├── messenger/
│   │   ├── handshake.hpp/cpp   # Kyber key exchange
│   │   ├── server.hpp/cpp      # Chat server
│   │   └── client.hpp/cpp      # Chat client
│   └── cli/
│       └── main.cpp            # CLI entry point
└── extern/
    └── liboqs/                 # Open Quantum Safe library
```

## License

MIT