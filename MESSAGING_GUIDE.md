# Secure Messaging System - Complete Guide

## Overview

The CryptoVault Secure Messaging System enables encrypted communication between users using industry-standard cryptographic protocols:

- **Key Exchange**: ECDH (Elliptic Curve Diffie-Hellman)
- **Encryption**: AES-256-GCM
- **Digital Signatures**: ECDSA (for non-repudiation)

---

## How It Works: Step-by-Step

### **Step 1: Initialize Your Messaging Session**

```
🔐 What happens:
1. You click "Initialize Messaging" button
2. Your frontend calls: GET /api/messaging/public_key/{your_username}
3. Backend generates an ECDH key pair and stores it in your session
4. Your public key is returned (Base64 encoded)
5. The public key appears in the "Your Public Key" textarea
```

**Why needed**: The public key is your identity in the messaging system. It's required for peers to encrypt messages that only you can decrypt.

**What to do**: Share this public key with your peer through any secure channel (email, in-person, QR code, etc.).

---

### **Step 2: Peer Shares Their Public Key**

```
🤝 What happens:
1. Your peer does the same (clicks "Initialize Messaging")
2. They share their generated public key with you
3. You paste their public key in the "Peer's Public Key" textarea
```

**Important**: This is a **manual key exchange**. In a real-world scenario, keys could be exchanged through:
- Manual copy-paste (as in this implementation)
- QR codes
- Out-of-band communication (phone call, in-person)
- Key server infrastructure (with trust verification)

---

### **Step 3: Establish Secure Session**

```
⚙️ What happens:
1. Select the user you want to chat with from the dropdown
2. The system automatically calls "Establish Session"
3. Backend receives your peer's public key
4. ECDH key exchange occurs:
   - Your private key + Peer's public key → Shared Secret
   - Peer's private key + Your public key → Same Shared Secret
5. This shared secret becomes the encryption key for all future messages
```

**Cryptographic Security**: The ECDH protocol ensures that even if someone intercepts the public keys, they cannot derive the shared secret without the private keys (which never leave either system).

---

### **Step 4: Send & Receive Messages**

```
📨 Sending a message:
1. Type your message
2. Click "📤 Send Message"
3. Frontend encrypts message with AES-256-GCM using the shared secret
4. Message is signed with ECDSA (your private key)
5. Encrypted + Signature sent to server
6. Server stores it for the recipient

📩 Receiving messages:
1. Click "📥 Check Messages"
2. Server retrieves encrypted messages for you
3. Frontend decrypts them with AES-256-GCM
4. Signature is verified (confirms sender's identity)
5. Messages displayed with ✅ (valid) or ❌ (invalid) signature indicator
```

---

## Technical Architecture

### Message Flow Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    ALICE (Sender)                            │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ 1. Initialize Messaging                              │   │
│  │    → Generate ECDH keypair                           │   │
│  │    → Get Public Key A                                │   │
│  └──────────────────────────────────────────────────────┘   │
│                         ↓ (share out-of-band)                │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                     BOB (Receiver)                            │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ 1. Initialize Messaging                              │   │
│  │    → Generate ECDH keypair                           │   │
│  │    → Get Public Key B                                │   │
│  └──────────────────────────────────────────────────────┘   │
│                         ↓ (share out-of-band)                │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                    ALICE (Sender)                            │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ 2. Establish Session with Bob                        │   │
│  │    → Paste Public Key B                              │   │
│  │    → ECDH(Private Key A + Public Key B) = Shared Secret │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                     BOB (Receiver)                            │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ 2. Establish Session with Alice                      │   │
│  │    → Paste Public Key A                              │   │
│  │    → ECDH(Private Key B + Public Key A) = Shared Secret │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                    ALICE (Sender)                            │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ 3. Send Message "Hello Bob"                          │   │
│  │    → AES-256-GCM.encrypt("Hello Bob", Shared Secret) │   │
│  │    → ECDSA.sign(encrypted_msg, Private Key A)        │   │
│  │    → Server stores encrypted message                 │   │
│  └──────────────────────────────────────────────────────┘   │
│                         ↓ (via server)                       │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                     BOB (Receiver)                            │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ 4. Check Messages                                    │   │
│  │    → Retrieve encrypted message                      │   │
│  │    → ECDSA.verify(signature, Public Key A)           │   │
│  │    → AES-256-GCM.decrypt(ciphertext, Shared Secret)  │   │
│  │    → Display: "Hello Bob" ✅                         │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

---

## Security Properties

### What's Protected?

| Property | Mechanism | Protection |
|----------|-----------|-----------|
| **Confidentiality** | AES-256-GCM | Only you and peer can read messages |
| **Integrity** | ECDH + AES-GCM (AEAD) | Message tampering is detected |
| **Authenticity** | ECDSA Digital Signature | Receiver can verify message came from sender |
| **Non-Repudiation** | ECDSA Signature | Sender cannot deny sending the message |

### What's NOT Protected?

- **Metadata**: Who is messaging whom, timestamps, message length
- **Server compromise**: If the server is compromised, the attacker can read stored encrypted messages (but not decrypt them without the shared secret)
- **Key compromise**: If your private key is stolen, your messages are at risk

---

## Common Issues & Troubleshooting

### Issue: "Initialize Messaging" button doesn't show public key

**Solution**: Make sure you are:
1. ✅ Logged in
2. ✅ In the "Secure Messaging" tab
3. ✅ Clicked the "Initialize Messaging" button
4. ✅ Check browser console for errors (F12 → Console)

### Issue: "Cannot establish session" error

**Solution**:
1. ✅ Make sure peer's public key is correctly pasted
2. ✅ Verify public key is in Base64 format
3. ✅ Check that both users have initialized messaging first

### Issue: Received messages show ❌ signature

**Causes**:
- Message was tampered with in transit
- Sender's key was compromised
- There's a bug in the signature verification

**Action**: Do not trust the message content!

---

## Example: Alice and Bob Chat

### Session Setup

**Alice's Actions:**
1. Logs in as "alice"
2. Clicks "Initialize Messaging"
3. Gets public key: `KF8DAQc...` (truncated)
4. Shares this with Bob via email: "Here's my public key"

**Bob's Actions:**
1. Logs in as "bob"
2. Clicks "Initialize Messaging"
3. Gets public key: `MIGbMBAGBy...` (truncated)
4. Shares this with Alice via email: "Here's my public key"

### Message Exchange

**Alice sending to Bob:**
1. Selects "bob" from user dropdown
2. Pastes Bob's public key in "Peer's Public Key" field
3. System automatically establishes session
4. Types: "Hey Bob, can you help with the project?"
5. Clicks "📤 Send Message"
6. Alice sees success message

**Bob checking messages:**
1. Logs in as "bob"
2. Goes to "Secure Messaging"
3. Selects "alice" from user dropdown
4. Pastes Alice's public key
5. System establishes session
6. Clicks "📥 Check Messages"
7. Sees: "alice [14:23:45] ✅ Hey Bob, can you help with the project?"

The ✅ means Alice's signature is valid, proving Alice sent this message.

---

## Implementation Details

### Frontend Changes Made

1. **Added `initializeMessaging()` function**:
   - Fetches user's public key from server
   - Displays it in the textarea for sharing
   - Uses `sessionStorage.getItem('username')` to get current user

2. **Updated login functions**:
   - Store username in `sessionStorage` after login
   - Enables `initializeMessaging()` to know which user is logged in

### Backend Integration

The backend provides these endpoints:

```python
# Get your public key
GET /api/messaging/public_key/{username}
Response: { "success": true, "public_key": "Base64String" }

# Establish session with peer
POST /api/messaging/establish_session
Body: { "peer_username": "...", "peer_public_key": "Base64String" }
Response: { "success": true, "our_public_key": "Base64String" }

# Send encrypted message
POST /api/messaging/send
Body: { "receiver": "...", "message": "...", "sign": true }
Response: { "success": true, "message": "..." }

# Receive encrypted messages
GET /api/messaging/receive
Response: { "success": true, "messages": [...] }
```

---

## Best Practices

1. **Always verify public keys** out-of-band before pasting
   - Compare key fingerprints if possible
   - Use multiple channels to verify
   - Watch for MITM attacks

2. **Keep your private keys safe**
   - Don't share your "Your Public Key" with attackers
   - Don't export private keys from the system
   - Use MFA to protect your account

3. **Check message signatures**
   - Always verify the ✅ icon
   - ❌ signatures mean do not trust the message

4. **For sensitive communications**
   - Consider using additional verification codes
   - Share fingerprints through a trusted channel
   - Confirm the other person is who they claim to be

---

## Files Modified

- `templates/index.html`: Added `initializeMessaging()` function and sessionStorage support
- Backend: Already had full support (no changes needed)

## References

- **ECDH**: https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman
- **AES-GCM**: https://en.wikipedia.org/wiki/Galois/Counter_Mode
- **ECDSA**: https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
