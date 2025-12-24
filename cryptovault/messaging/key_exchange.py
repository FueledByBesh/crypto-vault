"""
ECDH Key Exchange Implementation
Uses P-256 curve for ephemeral key exchange.
"""

import secrets
from typing import Tuple, Optional
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization


class ECDHKeyExchange:
    """
    Elliptic Curve Diffie-Hellman key exchange using P-256 curve.
    Generates ephemeral keys per session.
    """
    
    def __init__(self):
        """Initialize ECDH key exchange."""
        self.curve = ec.SECP256R1()  # P-256 curve
        self.backend = default_backend()
    
    def generate_key_pair(self) -> Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
        """
        Generate ephemeral key pair for this session.
        
        Returns:
            Tuple of (private_key, public_key)
        """
        private_key = ec.generate_private_key(self.curve, self.backend)
        public_key = private_key.public_key()
        return (private_key, public_key)
    
    def derive_shared_secret(self, private_key: ec.EllipticCurvePrivateKey,
                            peer_public_key: ec.EllipticCurvePublicKey) -> bytes:
        """
        Derive shared secret using ECDH.
        
        Args:
            private_key: Our private key
            peer_public_key: Peer's public key
            
        Returns:
            Shared secret bytes
        """
        shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
        return shared_secret
    
    def derive_session_key(self, shared_secret: bytes, salt: Optional[bytes] = None,
                          info: Optional[bytes] = None) -> bytes:
        """
        Derive session key from shared secret using HKDF.
        
        Args:
            shared_secret: ECDH shared secret
            salt: Optional salt for HKDF
            info: Optional context information
            
        Returns:
            32-byte session key for AES-256
        """
        if salt is None:
            salt = b"CryptoVaultSalt"
        
        if info is None:
            info = b"CryptoVault Session Key"
        
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits for AES-256
            salt=salt,
            info=info,
            backend=self.backend
        )
        
        return hkdf.derive(shared_secret)
    
    def serialize_public_key(self, public_key: ec.EllipticCurvePublicKey) -> bytes:
        """
        Serialize public key to bytes.
        
        Args:
            public_key: Public key to serialize
            
        Returns:
            Serialized public key bytes
        """
        return public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
    
    def deserialize_public_key(self, key_bytes: bytes) -> ec.EllipticCurvePublicKey:
        """
        Deserialize public key from bytes.
        
        Args:
            key_bytes: Serialized public key
            
        Returns:
            Deserialized public key
        """
        return ec.EllipticCurvePublicKey.from_encoded_point(
            self.curve,
            key_bytes
        )

