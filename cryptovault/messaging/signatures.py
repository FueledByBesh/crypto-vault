"""
Digital Signatures for Secure Messaging
Uses ECDSA (P-256) or Ed25519 for non-repudiation.
"""

from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


class DigitalSignature:
    """
    Digital signature implementation using ECDSA or Ed25519.
    Provides non-repudiation for messages.
    """
    
    def __init__(self, algorithm: str = "ECDSA"):
        """
        Initialize digital signature system.
        
        Args:
            algorithm: "ECDSA" (P-256) or "Ed25519"
        """
        self.algorithm = algorithm.upper()
        if self.algorithm not in ["ECDSA", "ED25519"]:
            raise ValueError("Algorithm must be ECDSA or Ed25519")
        self.backend = default_backend()
    
    def generate_key_pair(self) -> Tuple:
        """
        Generate signing key pair.
        
        Returns:
            Tuple of (private_key, public_key)
        """
        if self.algorithm == "ECDSA":
            private_key = ec.generate_private_key(ec.SECP256R1(), self.backend)
            public_key = private_key.public_key()
        else:  # Ed25519
            private_key = ed25519.Ed25519PrivateKey.generate()
            public_key = private_key.public_key()
        
        return (private_key, public_key)
    
    def sign(self, message: bytes, private_key) -> bytes:
        """
        Sign message.
        
        Args:
            message: Message to sign
            private_key: Private signing key
            
        Returns:
            Signature bytes
        """
        if self.algorithm == "ECDSA":
            signature = private_key.sign(
                message,
                ec.ECDSA(hashes.SHA256())
            )
        else:  # Ed25519
            signature = private_key.sign(message)
        
        return signature
    
    def verify(self, message: bytes, signature: bytes, public_key) -> bool:
        """
        Verify message signature.
        
        Args:
            message: Original message
            signature: Signature bytes
            public_key: Public verification key
            
        Returns:
            True if signature is valid
        """
        try:
            if self.algorithm == "ECDSA":
                public_key.verify(
                    signature,
                    message,
                    ec.ECDSA(hashes.SHA256())
                )
            else:  # Ed25519
                public_key.verify(signature, message)
            
            return True
        except InvalidSignature:
            return False
    
    def serialize_private_key(self, private_key) -> bytes:
        """
        Serialize private key to bytes.
        
        Args:
            private_key: Private key to serialize
            
        Returns:
            Serialized private key bytes (PEM format)
        """
        if self.algorithm == "ECDSA":
            return private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        else:  # Ed25519
            return private_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            )
    
    def serialize_public_key(self, public_key) -> bytes:
        """
        Serialize public key to bytes.
        
        Args:
            public_key: Public key to serialize
            
        Returns:
            Serialized public key bytes
        """
        if self.algorithm == "ECDSA":
            return public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        else:  # Ed25519
            return public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
    
    def deserialize_private_key(self, key_bytes: bytes):
        """
        Deserialize private key from bytes.
        
        Args:
            key_bytes: Serialized private key
            
        Returns:
            Deserialized private key
        """
        if self.algorithm == "ECDSA":
            return serialization.load_pem_private_key(
                key_bytes,
                password=None,
                backend=self.backend
            )
        else:  # Ed25519
            return ed25519.Ed25519PrivateKey.from_private_bytes(key_bytes)
    
    def deserialize_public_key(self, key_bytes: bytes):
        """
        Deserialize public key from bytes.
        
        Args:
            key_bytes: Serialized public key
            
        Returns:
            Deserialized public key
        """
        if self.algorithm == "ECDSA":
            return serialization.load_pem_public_key(
                key_bytes,
                backend=self.backend
            )
        else:  # Ed25519
            return ed25519.Ed25519PublicKey.from_public_bytes(key_bytes)

