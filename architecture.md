# CryptoVault Architecture Documentation

## System Architecture

CryptoVault is designed as a modular cryptographic security suite with clear separation of concerns.

## Module Overview

### 1. Core Crypto Library (`cryptovault/core/`)

**Purpose**: Educational from-scratch implementations of cryptographic primitives.

**Components**:
- `caesar.py`: Caesar cipher with frequency analysis attack
- `vigenere.py`: Vigenère cipher with Kasiski examination
- `sha256_simplified.py`: Simplified SHA-256 hash function
- `merkle_tree.py`: Merkle tree with proof generation/verification

**Design Decisions**:
- Implemented from scratch for educational purposes
- Clearly documented as non-production code
- Used by blockchain module for Merkle tree operations

### 2. Authentication Module (`cryptovault/auth/`)

**Purpose**: User authentication, password management, and MFA.

**Components**:
- `user_manager.py`: User registration, login, session management
- `mfa.py`: TOTP implementation (RFC 6238) with QR codes
- `password_validator.py`: Password strength validation

**Security Features**:
- Argon2id (preferred) or bcrypt for password hashing
- CSPRNG salt generation using `secrets` module
- Constant-time password verification
- Rate limiting and account lockout
- HMAC-SHA256 session tokens
- TOTP with time-window tolerance
- Hashed backup codes

**Data Flow**:
1. User registration → Password validation → Hashing → Storage
2. Login → Rate limit check → Password verification → Session token generation
3. MFA setup → TOTP secret generation → QR code → Backup codes

### 3. Secure Messaging Module (`cryptovault/messaging/`)

**Purpose**: End-to-end encrypted messaging with non-repudiation.

**Components**:
- `key_exchange.py`: ECDH key exchange (P-256 curve)
- `encryption.py`: AES-256-GCM encryption
- `signatures.py`: Digital signatures (ECDSA/Ed25519)
- `secure_messenger.py`: Integrated messaging system

**Security Features**:
- Ephemeral key pairs per session
- ECDH shared secret derivation
- HKDF for session key derivation
- Unique nonce per message (AES-GCM)
- Digital signatures for non-repudiation

**Message Format**:
- Encrypted: `nonce (12 bytes) || ciphertext || tag (16 bytes)`
- Signature: Separate signature bytes (optional)

**Data Flow**:
1. Session initialization → Generate ephemeral key pair
2. Key exchange → ECDH → HKDF → Session key
3. Message send → Encrypt → Sign → Transmit
4. Message receive → Verify signature → Decrypt

### 4. File Encryption Module (`cryptovault/file_encryption/`)

**Purpose**: Secure file encryption with streaming support.

**Components**:
- `file_encryptor.py`: Streaming encryption/decryption

**Security Features**:
- AES-256-GCM or ChaCha20-Poly1305
- Streaming encryption for large files (64 KB chunks)
- Random File Encryption Key (FEK)
- FEK encrypted with master key
- Master key derived via PBKDF2 or Argon2
- SHA-256 hash of original file
- HMAC-SHA256 integrity check

**File Format**:
```
[salt (16)] [fek_nonce (12)] [fek_len (4)] [encrypted_fek] 
[file_hash (32)] [hmac_salt (16)] 
[chunk_nonce (12)] [chunk_len (4)] [encrypted_chunk] ... 
[hmac (32)]
```

**Data Flow**:
1. Encryption: Generate FEK → Encrypt FEK → Calculate hash → Stream encrypt → HMAC
2. Decryption: Read header → Decrypt FEK → Stream decrypt → Verify HMAC → Verify hash

### 5. Blockchain Audit Ledger (`cryptovault/blockchain/`)

**Purpose**: Immutable audit trail for security events.

**Components**:
- `block.py`: Block structure and transactions
- `proof_of_work.py`: Adjustable difficulty PoW
- `blockchain.py`: Chain management and validation

**Block Structure**:
- Index
- Timestamp
- Previous hash
- Nonce (for PoW)
- Merkle root
- Transactions

**Security Features**:
- Merkle tree for transaction integrity
- Proof of Work (adjustable difficulty)
- Chain validation and integrity checks
- Merkle proof generation/verification

**Data Flow**:
1. Security event → Create transaction → Add to pending pool
2. Mining → Build Merkle tree → Find nonce → Add block to chain
3. Validation → Verify PoW → Verify Merkle root → Verify chain links

### 6. Audit Logging (`cryptovault/logging/`)

**Purpose**: Secure logging of security-sensitive actions.

**Components**:
- `audit_logger.py`: Secure logging with hashed sensitive fields

**Security Features**:
- SHA-256 hashing of sensitive fields (username, IP, file paths)
- JSON-formatted logs
- Append-only log file

**Log Format**:
```json
{
  "timestamp": 1234567890.123,
  "event_type": "login_attempt",
  "success": true,
  "username_hash": "...",
  "ip_hash": "...",
  "details": {...}
}
```

## Integration Layer

The `CryptoVault` class (`cryptovault/cryptovault.py`) integrates all modules:

1. **Initialization**: Creates instances of all modules
2. **User Management**: Wraps authentication with audit logging
3. **Event Logging**: All security events logged to audit log and blockchain
4. **Session Management**: Per-user messaging and file encryption sessions

## Data Flow Examples

### User Registration Flow
```
User → CryptoVault.register_user()
  → UserManager.register_user()
    → PasswordValidator.validate()
    → Hash password (Argon2id/bcrypt)
    → Store user
  → AuditLogger.log()
  → Blockchain.create_transaction()
  → Blockchain.mine_pending_transactions()
```

### File Encryption Flow
```
User → CryptoVault.encrypt_file()
  → FileEncryptor.encrypt_file()
    → Derive master key (PBKDF2/Argon2)
    → Generate FEK
    → Encrypt FEK
    → Stream encrypt file
    → Calculate HMAC
  → AuditLogger.log_file_encryption()
  → Blockchain.create_transaction()
```

### Secure Messaging Flow
```
User A → CryptoVault.send_message()
  → SecureMessenger.send_message()
    → MessageEncryption.encrypt()
    → DigitalSignature.sign()
  → AuditLogger.log_messaging_event()
  → Blockchain.create_transaction()
  
User B → CryptoVault.receive_message()
  → SecureMessenger.receive_message()
    → DigitalSignature.verify()
    → MessageEncryption.decrypt()
```

## Security Considerations

1. **Key Management**: 
   - Session keys are ephemeral (per session)
   - Master keys derived from passwords (not stored)
   - FEKs encrypted with master keys

2. **Randomness**: 
   - All random values use `secrets` module (CSPRNG)
   - No insecure random number generation

3. **Timing Attacks**: 
   - Constant-time password verification
   - Constant-time HMAC comparison

4. **Information Leakage**: 
   - Sensitive fields hashed in logs
   - No secrets in log files
   - Error messages don't reveal user existence

5. **Integrity**: 
   - HMAC for file integrity
   - Digital signatures for message integrity
   - Blockchain for audit trail integrity

## Extensibility

The modular design allows for:
- Adding new encryption algorithms
- Supporting additional signature schemes
- Extending blockchain functionality
- Adding new audit event types

