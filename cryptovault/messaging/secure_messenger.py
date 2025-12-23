"""
Secure Messaging System
Integrates ECDH key exchange, AES-GCM encryption, and digital signatures.
"""

from typing import Tuple, Optional
from cryptography.hazmat.primitives.asymmetric import ec
from cryptovault.messaging.key_exchange import ECDHKeyExchange
from cryptovault.messaging.encryption import MessageEncryption
from cryptovault.messaging.signatures import DigitalSignature


class SecureMessenger:
    """
    Complete secure messaging system with:
    - ECDH key exchange (P-256)
    - Ephemeral keys per session
    - AES-256-GCM encryption
    - Digital signatures for non-repudiation
    """
    
    def __init__(self, signature_algorithm: str = "ECDSA"):
        """
        Initialize secure messenger.
        
        Args:
            signature_algorithm: "ECDSA" or "Ed25519"
        """
        self.key_exchange = ECDHKeyExchange()
        self.signature = DigitalSignature(signature_algorithm)
        
        # Per-session state
        self.private_key: Optional[ec.EllipticCurvePrivateKey] = None
        self.public_key: Optional[ec.EllipticCurvePublicKey] = None
        self.session_key: Optional[bytes] = None
        self.encryption: Optional[MessageEncryption] = None
        self.signing_key: Optional = None
        self.verification_key: Optional = None
    
    def initialize_session(self) -> bytes:
        """
        Initialize new session with ephemeral keys.
        
        Returns:
            Serialized public key to send to peer
        """
        # Generate ECDH key pair
        self.private_key, self.public_key = self.key_exchange.generate_key_pair()
        
        # Generate signing key pair
        self.signing_key, self.verification_key = self.signature.generate_key_pair()
        
        return self.key_exchange.serialize_public_key(self.public_key)
    
    def establish_session(self, peer_public_key_bytes: bytes,
                         peer_verification_key_bytes: Optional[bytes] = None) -> Tuple[bytes, Optional[bytes]]:
        """
        Establish session with peer's public key.
        
        Args:
            peer_public_key_bytes: Peer's ECDH public key
            peer_verification_key_bytes: Peer's signature verification key (optional)
            
        Returns:
            Tuple of (our_public_key_bytes, our_verification_key_bytes)
        """
        # Initialize our session
        our_public_key_bytes = self.initialize_session()
        
        # Deserialize peer's public key
        peer_public_key = self.key_exchange.deserialize_public_key(peer_public_key_bytes)
        
        # Derive shared secret
        shared_secret = self.key_exchange.derive_shared_secret(
            self.private_key,
            peer_public_key
        )
        
        # Derive session key using HKDF
        self.session_key = self.key_exchange.derive_session_key(shared_secret)
        
        # Initialize encryption
        self.encryption = MessageEncryption(self.session_key)
        
        # Store peer's verification key if provided
        if peer_verification_key_bytes:
            self.peer_verification_key = self.signature.deserialize_public_key(
                peer_verification_key_bytes
            )
        else:
            self.peer_verification_key = None
        
        our_verification_key_bytes = self.signature.serialize_public_key(
            self.verification_key
        )
        
        return (our_public_key_bytes, our_verification_key_bytes)
    
    def send_message(self, message: str, sign: bool = True) -> Tuple[bytes, Optional[bytes]]:
        """
        Encrypt and optionally sign message.
        
        Args:
            message: Plaintext message
            sign: Whether to sign the message
            
        Returns:
            Tuple of (encrypted_message, signature)
        """
        if not self.encryption:
            raise ValueError("Session not established")
        
        # Encrypt message
        encrypted = self.encryption.encrypt_message(message)
        
        # Sign if requested
        signature = None
        if sign and self.signing_key:
            signature = self.signature.sign(encrypted, self.signing_key)
        
        return (encrypted, signature)
    
    def receive_message(self, encrypted_message: bytes,
                       signature: Optional[bytes] = None) -> Tuple[str, bool]:
        """
        Decrypt and verify message.
        
        Args:
            encrypted_message: Encrypted message
            signature: Optional signature to verify
            
        Returns:
            Tuple of (decrypted_message, signature_valid)
        """
        if not self.encryption:
            raise ValueError("Session not established")
        
        # Verify signature if provided
        signature_valid = False
        if signature and self.peer_verification_key:
            signature_valid = self.signature.verify(
                encrypted_message,
                signature,
                self.peer_verification_key
            )
        elif not signature:
            signature_valid = True  # No signature to verify
        
        # Decrypt message
        try:
            decrypted = self.encryption.decrypt_message(encrypted_message)
            return (decrypted, signature_valid)
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")

