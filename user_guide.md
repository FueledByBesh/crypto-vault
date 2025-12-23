# CryptoVault User Guide

## Introduction

CryptoVault is a cryptographic security suite providing secure authentication, messaging, file encryption, and audit logging. This guide explains how to use each feature.

## Installation

1. Install Python 3.8 or higher
2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Basic Usage

### Initialization

```python
from cryptovault.cryptovault import CryptoVault

# Create CryptoVault instance
vault = CryptoVault()
```

### User Registration

Register a new user with a strong password:

```python
success, message = vault.register_user("alice", "SecurePass123!")
if success:
    print("Registration successful!")
else:
    print(f"Registration failed: {message}")
```

**Password Requirements**:
- Minimum 12 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one digit
- At least one special character
- No obvious sequential patterns

### Login

Authenticate with username and password:

```python
success, token, message = vault.login("alice", "SecurePass123!", ip_address="192.168.1.1")
if success:
    print(f"Login successful! Token: {token}")
else:
    print(f"Login failed: {message}")
```

**Note**: After 5 failed login attempts, the account is locked for 15 minutes.

### Session Verification

Verify a session token:

```python
is_valid, username = vault.verify_session(token)
if is_valid:
    print(f"Session valid for user: {username}")
```

## Multi-Factor Authentication (MFA)

### Setup MFA

Enable MFA for your account:

```python
success, secret, backup_codes, qr_code = vault.setup_mfa("alice", "SecurePass123!")
if success:
    # Save QR code to file
    with open("mfa_qr.png", "wb") as f:
        f.write(qr_code)
    
    # Save backup codes securely
    print("Backup codes:", backup_codes)
    print("Scan QR code with authenticator app (Google Authenticator, Authy, etc.)")
```

**Important**: 
- Save backup codes in a secure location
- Each backup code can only be used once
- QR code contains the TOTP secret

### Verify MFA Code

After login, verify MFA code:

```python
# Get code from authenticator app
code = input("Enter 6-digit code: ")

is_valid = vault.verify_mfa("alice", code)
if is_valid:
    print("MFA verified!")
else:
    print("Invalid code")
```

**Using Backup Codes**:
```python
# Use backup code instead of TOTP
backup_code = input("Enter backup code: ")
is_valid = vault.verify_mfa("alice", backup_code)
```

## File Encryption

### Encrypt a File

Encrypt a file with a password:

```python
# Encrypt file
metadata = vault.encrypt_file(
    username="alice",
    input_path="document.txt",
    output_path="document.encrypted",
    password="filepassword123",
    algorithm="AES-GCM"  # or "ChaCha20-Poly1305"
)

print(f"File encrypted! Hash: {metadata['file_hash']}")
```

**File Format**: The encrypted file contains:
- Salt for key derivation
- Encrypted File Encryption Key (FEK)
- Original file hash
- HMAC salt
- Encrypted file chunks
- HMAC for integrity

### Decrypt a File

Decrypt an encrypted file:

```python
# Decrypt file
result = vault.decrypt_file(
    username="alice",
    input_path="document.encrypted",
    output_path="document_decrypted.txt",
    password="filepassword123"
)

if result['hash_verified'] and result['hmac_verified']:
    print("File decrypted and integrity verified!")
else:
    print("Warning: Integrity verification failed!")
```

**Integrity Checks**:
- HMAC verification ensures file wasn't tampered
- File hash verification ensures correct decryption

## Secure Messaging

### Initialize Messaging Session

Set up secure messaging:

```python
# User A initializes session
alice_pub_key = vault.initialize_messaging("alice")

# User B initializes session
bob_pub_key = vault.initialize_messaging("bob")
```

### Establish Session with Peer

Exchange public keys and establish session:

```python
# Alice establishes session with Bob
alice_pub, alice_verif = vault.establish_messaging_session("alice", bob_pub_key)

# Bob establishes session with Alice
bob_pub, bob_verif = vault.establish_messaging_session("bob", alice_pub_key, alice_verif)
```

### Send Encrypted Message

Send an encrypted and signed message:

```python
# Alice sends message to Bob
message = "Hello, Bob! This is a secret message."
encrypted, signature = vault.send_message("alice", message, sign=True)

# Transmit encrypted and signature to Bob
```

### Receive and Decrypt Message

Receive and decrypt a message:

```python
# Bob receives message from Alice
decrypted, sig_valid = vault.receive_message("bob", encrypted, signature)

if sig_valid:
    print(f"Message from Alice: {decrypted}")
    print("Signature verified!")
else:
    print("Warning: Signature verification failed!")
```

**Security Features**:
- Messages encrypted with AES-256-GCM
- Unique nonce per message
- Digital signatures for non-repudiation
- Ephemeral keys per session

## Blockchain Audit Ledger

### View Blockchain Information

Get blockchain statistics:

```python
info = vault.get_blockchain_info()
print(f"Chain length: {info['length']}")
print(f"Total transactions: {info['total_transactions']}")
print(f"Pending transactions: {info['pending_transactions']}")
print(f"Chain valid: {info['is_valid']}")
```

### Validate Blockchain

Verify blockchain integrity:

```python
is_valid, error = vault.validate_blockchain()
if is_valid:
    print("Blockchain is valid!")
else:
    print(f"Blockchain validation failed: {error}")
```

**Note**: All security events (login, file encryption, messaging) are automatically recorded in the blockchain.

## Audit Logging

### View Recent Audit Logs

Retrieve recent audit log entries:

```python
logs = vault.get_recent_audit_logs(limit=50)
for log in logs:
    print(f"{log['event_type']}: {log['success']} at {log['timestamp']}")
```

**Log Events**:
- `user_registration`: New user registration
- `login_attempt`: Login attempts (success/failure)
- `file_encrypt`: File encryption events
- `file_decrypt`: File decryption events
- `messaging`: Secure messaging events
- `mfa_setup`: MFA setup events

**Security Note**: Sensitive fields (username, IP, file paths) are hashed in logs.

## Error Handling

### Common Errors

**Registration Errors**:
- `"Username already exists"`: Username is taken
- `"Password must be at least 12 characters long"`: Password too short
- `"Password must contain at least one uppercase letter"`: Missing requirements

**Login Errors**:
- `"Invalid username or password"`: Wrong credentials
- `"Account locked. Try again in X seconds"`: Too many failed attempts

**File Encryption Errors**:
- `"Invalid file format"`: Corrupted encrypted file
- `"Decryption failed"`: Wrong password or tampered file
- `"HMAC verification failed"`: File integrity compromised

**Messaging Errors**:
- `"Messaging session not initialized"`: Session not set up
- `"Session not established"`: Key exchange not completed
- `"Decryption failed"`: Invalid message or key mismatch

## Best Practices

1. **Password Security**:
   - Use strong, unique passwords
   - Don't reuse passwords
   - Store passwords securely (password manager)

2. **MFA**:
   - Always enable MFA for important accounts
   - Store backup codes securely
   - Don't share TOTP secrets

3. **File Encryption**:
   - Use strong passwords for file encryption
   - Verify integrity after decryption
   - Keep encrypted backups

4. **Secure Messaging**:
   - Verify signatures on all messages
   - Use ephemeral keys (new session per conversation)
   - Don't share private keys

5. **Audit Logs**:
   - Regularly review audit logs
   - Monitor for suspicious activity
   - Keep logs secure

## Examples

### Complete Workflow

```python
from cryptovault.cryptovault import CryptoVault

# Initialize
vault = CryptoVault()

# Register and login
vault.register_user("alice", "SecurePass123!")
success, token, _ = vault.login("alice", "SecurePass123!")

# Setup MFA
vault.setup_mfa("alice", "SecurePass123!")

# Encrypt file
vault.encrypt_file("alice", "secret.txt", "secret.enc", "filepass")

# Decrypt file
vault.decrypt_file("alice", "secret.enc", "secret_decrypted.txt", "filepass")

# Secure messaging
vault.register_user("bob", "SecurePass456!")
vault.login("bob", "SecurePass456!")

alice_pub = vault.initialize_messaging("alice")
bob_pub = vault.initialize_messaging("bob")

vault.establish_messaging_session("alice", bob_pub)
vault.establish_messaging_session("bob", alice_pub)

encrypted, sig = vault.send_message("alice", "Hello Bob!")
message, valid = vault.receive_message("bob", encrypted, sig)

# Check blockchain
info = vault.get_blockchain_info()
print(f"Total transactions: {info['total_transactions']}")
```

## Troubleshooting

**Issue**: "No password hashing library available"
**Solution**: Install argon2-cffi or bcrypt: `pip install argon2-cffi`

**Issue**: "QR code generation fails"
**Solution**: Install qrcode and Pillow: `pip install qrcode Pillow`

**Issue**: "File decryption fails"
**Solution**: 
- Verify correct password
- Check file integrity (HMAC verification)
- Ensure file wasn't corrupted

**Issue**: "Messaging session errors"
**Solution**:
- Ensure both users initialized sessions
- Verify key exchange completed
- Check signature verification

## Support

For issues or questions:
1. Review this user guide
2. Check architecture documentation
3. Review security analysis
4. Run tests: `pytest`

## Security Reminders

⚠️ **Important**:
- This is an educational project
- Don't use for production without security audit
- Keep passwords and keys secure
- Regularly review audit logs
- Enable MFA for all accounts

