# CryptoVault – Cryptographic Security Suite

A comprehensive cryptographic security system implementing authentication, secure messaging, file encryption, and blockchain audit logging.

## Overview

CryptoVault is a final exam project demonstrating practical cryptographic implementations. It includes:

- **Authentication Module**: User registration, login, MFA (TOTP), session management
- **Secure Messaging Module**: ECDH key exchange, AES-256-GCM encryption, digital signatures
- **File Encryption Module**: Streaming encryption with AES-GCM/ChaCha20-Poly1305
- **Blockchain Audit Ledger**: Immutable audit trail with Merkle trees and Proof of Work
- **Core Crypto Library**: From-scratch implementations (Caesar, Vigenère, SHA-256, Merkle trees)

## Features

### Security Features
- ✅ Password strength validation
- ✅ Argon2id/bcrypt password hashing
- ✅ Constant-time password verification
- ✅ Rate limiting and account lockout
- ✅ HMAC-SHA256 session tokens
- ✅ TOTP-based MFA (RFC 6238)
- ✅ Backup codes for MFA recovery
- ✅ ECDH key exchange (P-256)
- ✅ Ephemeral keys per session
- ✅ AES-256-GCM encryption
- ✅ Digital signatures (ECDSA/Ed25519)
- ✅ Streaming file encryption
- ✅ HMAC integrity verification
- ✅ Blockchain-based audit logging
- ✅ Secure hashing of sensitive log fields

### From-Scratch Implementations
1. **Caesar Cipher** with frequency analysis attack
2. **Vigenère Cipher** with Kasiski examination
3. **Simplified SHA-256** hash function
4. **Merkle Tree** with proof generation/verification

## Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Setup

1. Clone or download this repository:
```bash
cd Crypto
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run tests:
```bash
pytest
```

## Quick Start

```python
from cryptovault.cryptovault import CryptoVault

# Initialize system
vault = CryptoVault()

# Register user
vault.register_user("alice", "SecurePass123!")

# Login
success, token, msg = vault.login("alice", "SecurePass123!")

# Setup MFA
success, secret, backup_codes, qr_code = vault.setup_mfa("alice", "SecurePass123!")

# Encrypt file
vault.encrypt_file("alice", "document.txt", "document.enc", "filepassword")

# Decrypt file
vault.decrypt_file("alice", "document.enc", "document_decrypted.txt", "filepassword")
```

## Project Structure

```
Crypto/
├── cryptovault/
│   ├── __init__.py
│   ├── cryptovault.py          # Main integration layer
│   ├── core/                    # From-scratch crypto implementations
│   │   ├── caesar.py
│   │   ├── vigenere.py
│   │   ├── sha256_simplified.py
│   │   └── merkle_tree.py
│   ├── auth/                    # Authentication module
│   │   ├── user_manager.py
│   │   ├── mfa.py
│   │   └── password_validator.py
│   ├── messaging/               # Secure messaging module
│   │   ├── key_exchange.py
│   │   ├── encryption.py
│   │   ├── signatures.py
│   │   └── secure_messenger.py
│   ├── file_encryption/         # File encryption module
│   │   └── file_encryptor.py
│   ├── blockchain/              # Blockchain audit ledger
│   │   ├── block.py
│   │   ├── proof_of_work.py
│   │   └── blockchain.py
│   └── logging/                 # Audit logging
│       └── audit_logger.py
├── tests/                       # Test suite
│   ├── test_core.py
│   ├── test_auth.py
│   └── test_integration.py
├── requirements.txt
├── pytest.ini
└── README.md
```

## Documentation

- [Architecture Documentation](architecture.md)
- [Security Analysis](security_analysis.md)
- [User Guide](user_guide.md)

## Testing

Run all tests:
```bash
pytest
```

Run with coverage:
```bash
pytest --cov=cryptovault --cov-report=html
```

## Security Notes

⚠️ **Important**: This is an educational project for academic purposes. Some implementations (Caesar, Vigenère, simplified SHA-256) are for learning and should NOT be used in production.

For production use:
- Always use standard library `hashlib.sha256()` instead of simplified version
- Use established cryptographic libraries (cryptography, PyCryptodome)
- Follow security best practices and get professional security audits

## License

This project is for educational purposes only.

## Author

Final Exam Project - Cryptographic Security Suite

