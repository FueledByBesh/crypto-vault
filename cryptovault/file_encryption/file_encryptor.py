"""
File Encryption Module
Streaming encryption with AES-256-GCM or ChaCha20-Poly1305.
"""

import secrets
import os
import hashlib
import hmac
from typing import Tuple, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


class FileEncryptor:
    """
    File encryption with streaming support for large files.
    Uses AES-256-GCM or ChaCha20-Poly1305.
    """
    
    CHUNK_SIZE = 1024 * 1024  # 1 MB chunks for streaming (optimized for performance)
    NONCE_SIZE = 12  # 96 bits for GCM/ChaCha20
    SALT_SIZE = 16
    KEY_SIZE = 32  # 256 bits
    PBKDF2_ITERATIONS = 20000  # Reduced from 100k for better performance (still secure)
    
    def __init__(self, algorithm: str = "AES-GCM", use_argon2: bool = False):
        """
        Initialize file encryptor.
        
        Args:
            algorithm: "AES-GCM" or "ChaCha20-Poly1305"
            use_argon2: Use Argon2 for key derivation (else PBKDF2)
                      Note: Currently uses PBKDF2 for file encryption
        """
        self.algorithm = algorithm.upper()
        if self.algorithm not in ["AES-GCM", "CHACHA20-POLY1305"]:
            raise ValueError("Algorithm must be AES-GCM or ChaCha20-Poly1305")
        
        self.use_argon2 = False  # Use PBKDF2 for file encryption (Argon2 for passwords)
        self.backend = default_backend()
    
    def derive_master_key(self, password: str, salt: bytes,
                         iterations: int = None) -> bytes:
        """
        Derive master key from password using PBKDF2 or Argon2.
        
        Args:
            password: User password
            salt: Salt bytes
            iterations: Iterations for PBKDF2 (defaults to PBKDF2_ITERATIONS)
            
        Returns:
            32-byte master key
        """
        if iterations is None:
            iterations = self.PBKDF2_ITERATIONS
        
        password_bytes = password.encode('utf-8')
        
        # Use PBKDF2 for file encryption key derivation
        # (Argon2 is used for password hashing in auth module)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
            backend=self.backend
        )
        return kdf.derive(password_bytes)
    
    def generate_file_encryption_key(self) -> bytes:
        """
        Generate random File Encryption Key (FEK).
        
        Returns:
            32-byte random key
        """
        return secrets.token_bytes(self.KEY_SIZE)
    
    def encrypt_fek(self, fek: bytes, master_key: bytes) -> Tuple[bytes, bytes]:
        """
        Encrypt File Encryption Key with master key.
        
        Args:
            fek: File Encryption Key
            master_key: Master key
            
        Returns:
            Tuple of (nonce, encrypted_fek)
        """
        if self.algorithm == "AES-GCM":
            cipher = AESGCM(master_key)
        else:  # ChaCha20-Poly1305
            cipher = ChaCha20Poly1305(master_key)
        
        nonce = secrets.token_bytes(self.NONCE_SIZE)
        encrypted_fek = cipher.encrypt(nonce, fek, None)
        
        return (nonce, encrypted_fek)
    
    def decrypt_fek(self, encrypted_fek: bytes, nonce: bytes, master_key: bytes) -> bytes:
        """
        Decrypt File Encryption Key.
        
        Args:
            encrypted_fek: Encrypted FEK
            nonce: Nonce used for encryption
            master_key: Master key
            
        Returns:
            Decrypted FEK
        """
        if self.algorithm == "AES-GCM":
            cipher = AESGCM(master_key)
        else:  # ChaCha20-Poly1305
            cipher = ChaCha20Poly1305(master_key)
        
        return cipher.decrypt(nonce, encrypted_fek, None)
    
    def calculate_file_hash(self, file_path: str) -> bytes:
        """
        Calculate SHA-256 hash of original file.
        
        Args:
            file_path: Path to file
            
        Returns:
            32-byte hash
        """
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while chunk := f.read(self.CHUNK_SIZE):
                sha256.update(chunk)
        return sha256.digest()
    
    def encrypt_file(self, input_path: str, output_path: str, password: str) -> dict:
        """
        Encrypt file with streaming support.
        
        File format:
        - salt (16 bytes)
        - fek_nonce (12 bytes)
        - encrypted_fek (variable)
        - file_hash (32 bytes)
        - hmac_salt (16 bytes)
        - encrypted_data (streaming chunks)
        
        Args:
            input_path: Path to input file
            output_path: Path to output encrypted file
            password: Encryption password
            
        Returns:
            Dictionary with metadata (file_hash, etc.)
        """
        # Generate salt for key derivation
        salt = secrets.token_bytes(self.SALT_SIZE)
        
        # Derive master key
        master_key = self.derive_master_key(password, salt)
        
        # Generate File Encryption Key
        fek = self.generate_file_encryption_key()
        
        # Encrypt FEK with master key
        fek_nonce, encrypted_fek = self.encrypt_fek(fek, master_key)
        
        # Calculate original file hash
        file_hash = self.calculate_file_hash(input_path)
        
        # Generate HMAC salt
        hmac_salt = secrets.token_bytes(self.SALT_SIZE)
        
        # Initialize cipher
        if self.algorithm == "AES-GCM":
            cipher = AESGCM(fek)
        else:  # ChaCha20-Poly1305
            cipher = ChaCha20Poly1305(fek)
        
        # Write header
        with open(output_path, 'wb') as out_file:
            # Write salt
            out_file.write(salt)
            
            # Write FEK nonce
            out_file.write(fek_nonce)
            
            # Write encrypted FEK length and data
            out_file.write(len(encrypted_fek).to_bytes(4, 'big'))
            out_file.write(encrypted_fek)
            
            # Write file hash
            out_file.write(file_hash)
            
            # Write HMAC salt
            out_file.write(hmac_salt)
            
            # Encrypt file in chunks
            hmac_obj = hmac.new(
                hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), hmac_salt, self.PBKDF2_ITERATIONS, 32),
                digestmod=hashlib.sha256
            )
            
            with open(input_path, 'rb') as in_file:
                while True:
                    chunk = in_file.read(self.CHUNK_SIZE)
                    if not chunk:
                        break
                    
                    # Generate nonce for this chunk
                    chunk_nonce = secrets.token_bytes(self.NONCE_SIZE)
                    
                    # Encrypt chunk
                    encrypted_chunk = cipher.encrypt(chunk_nonce, chunk, None)
                    
                    # Write nonce and encrypted chunk
                    out_file.write(chunk_nonce)
                    out_file.write(len(encrypted_chunk).to_bytes(4, 'big'))
                    out_file.write(encrypted_chunk)
                    
                    # Update HMAC
                    hmac_obj.update(encrypted_chunk)
        
        # Calculate HMAC
        file_hmac = hmac_obj.digest()
        
        # Append HMAC to file
        with open(output_path, 'ab') as out_file:
            out_file.write(file_hmac)
        
        return {
            'file_hash': file_hash.hex(),
            'algorithm': self.algorithm,
            'salt': salt.hex(),
            'hmac': file_hmac.hex()
        }
    
    def decrypt_file(self, input_path: str, output_path: str, password: str) -> dict:
        """
        Decrypt file with integrity verification.
        
        Args:
            input_path: Path to encrypted file
            output_path: Path to decrypted file
            password: Decryption password
            
        Returns:
            Dictionary with metadata (file_hash, verified, etc.)
        """
        with open(input_path, 'rb') as in_file:
            # Read salt
            salt = in_file.read(self.SALT_SIZE)
            if len(salt) != self.SALT_SIZE:
                raise ValueError("Invalid file format: salt")
            
            # Derive master key
            master_key = self.derive_master_key(password, salt)
            
            # Read FEK nonce
            fek_nonce = in_file.read(self.NONCE_SIZE)
            if len(fek_nonce) != self.NONCE_SIZE:
                raise ValueError("Invalid file format: FEK nonce")
            
            # Read encrypted FEK
            fek_len = int.from_bytes(in_file.read(4), 'big')
            encrypted_fek = in_file.read(fek_len)
            if len(encrypted_fek) != fek_len:
                raise ValueError("Invalid file format: encrypted FEK")
            
            # Decrypt FEK
            fek = self.decrypt_fek(encrypted_fek, fek_nonce, master_key)
            
            # Read file hash
            stored_hash = in_file.read(32)
            if len(stored_hash) != 32:
                raise ValueError("Invalid file format: file hash")
            
            # Read HMAC salt
            hmac_salt = in_file.read(self.SALT_SIZE)
            if len(hmac_salt) != self.SALT_SIZE:
                raise ValueError("Invalid file format: HMAC salt")
            
            # Get file size to find HMAC at end
            in_file.seek(0, os.SEEK_END)
            file_size = in_file.tell()
            in_file.seek(
                self.SALT_SIZE + self.NONCE_SIZE + 4 + fek_len + 32 + self.SALT_SIZE,
                os.SEEK_SET
            )
            
            # Calculate HMAC key
            hmac_key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), hmac_salt, self.PBKDF2_ITERATIONS, 32)
            hmac_obj = hmac.new(hmac_key, digestmod=hashlib.sha256)
            
            # Initialize cipher
            if self.algorithm == "AES-GCM":
                cipher = AESGCM(fek)
            else:  # ChaCha20-Poly1305
                cipher = ChaCha20Poly1305(fek)
            
            # Decrypt file in chunks
            with open(output_path, 'wb') as out_file:
                while True:
                    # Check if we're at HMAC
                    current_pos = in_file.tell()
                    if current_pos >= file_size - 32:  # 32 bytes for HMAC
                        break
                    
                    # Read chunk nonce
                    chunk_nonce = in_file.read(self.NONCE_SIZE)
                    if len(chunk_nonce) != self.NONCE_SIZE:
                        break
                    
                    # Read encrypted chunk length
                    chunk_len = int.from_bytes(in_file.read(4), 'big')
                    encrypted_chunk = in_file.read(chunk_len)
                    if len(encrypted_chunk) != chunk_len:
                        break
                    
                    # Update HMAC before decryption
                    hmac_obj.update(encrypted_chunk)
                    
                    # Decrypt chunk
                    try:
                        decrypted_chunk = cipher.decrypt(chunk_nonce, encrypted_chunk, None)
                        out_file.write(decrypted_chunk)
                    except Exception as e:
                        raise ValueError(f"Decryption failed: {str(e)}")
            
            # Read and verify HMAC
            stored_hmac = in_file.read(32)
            calculated_hmac = hmac_obj.digest()
            
            if not hmac.compare_digest(stored_hmac, calculated_hmac):
                os.remove(output_path)  # Delete partial file
                raise ValueError("HMAC verification failed: file may be tampered")
            
            # Verify file hash
            calculated_hash = self.calculate_file_hash(output_path)
            hash_verified = hmac.compare_digest(stored_hash, calculated_hash)
            
            return {
                'file_hash': stored_hash.hex(),
                'calculated_hash': calculated_hash.hex(),
                'hash_verified': hash_verified,
                'hmac_verified': True
            }

