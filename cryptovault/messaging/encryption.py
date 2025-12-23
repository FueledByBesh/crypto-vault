"""
Secure Messaging Encryption
AES-256-GCM encryption with unique nonces per message.
"""

import secrets
from typing import Tuple, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend


class MessageEncryption:
    """
    AES-256-GCM encryption for secure messaging.
    Uses unique nonce per message.
    """
    
    NONCE_SIZE = 12  # 96 bits for GCM (recommended)
    
    def __init__(self, key: bytes):
        """
        Initialize message encryption with session key.
        
        Args:
            key: 32-byte AES-256 key
        """
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes for AES-256")
        self.key = key
        self.aesgcm = AESGCM(key)
    
    def encrypt(self, plaintext: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """
        Encrypt message using AES-256-GCM.
        
        Message format: nonce (12 bytes) || ciphertext || tag (16 bytes)
        
        Args:
            plaintext: Message to encrypt
            associated_data: Optional associated data (not encrypted, but authenticated)
            
        Returns:
            Encrypted message: nonce || ciphertext || tag
        """
        # Generate unique nonce (CSPRNG)
        nonce = secrets.token_bytes(self.NONCE_SIZE)
        
        # Encrypt
        ciphertext = self.aesgcm.encrypt(nonce, plaintext, associated_data)
        
        # Format: nonce || ciphertext (includes tag)
        return nonce + ciphertext
    
    def decrypt(self, ciphertext: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """
        Decrypt message using AES-256-GCM.
        
        Args:
            ciphertext: Encrypted message (nonce || ciphertext || tag)
            associated_data: Optional associated data
            
        Returns:
            Decrypted plaintext
            
        Raises:
            ValueError: If decryption fails (authentication failure)
        """
        if len(ciphertext) < self.NONCE_SIZE + 16:  # nonce + minimum tag
            raise ValueError("Ciphertext too short")
        
        # Extract nonce and encrypted data
        nonce = ciphertext[:self.NONCE_SIZE]
        encrypted_data = ciphertext[self.NONCE_SIZE:]
        
        # Decrypt (includes tag verification)
        try:
            plaintext = self.aesgcm.decrypt(nonce, encrypted_data, associated_data)
            return plaintext
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")
    
    def encrypt_message(self, message: str) -> bytes:
        """
        Encrypt text message.
        
        Args:
            message: Text message to encrypt
            
        Returns:
            Encrypted message bytes
        """
        return self.encrypt(message.encode('utf-8'))
    
    def decrypt_message(self, ciphertext: bytes) -> str:
        """
        Decrypt text message.
        
        Args:
            ciphertext: Encrypted message bytes
            
        Returns:
            Decrypted text message
        """
        plaintext = self.decrypt(ciphertext)
        return plaintext.decode('utf-8')

