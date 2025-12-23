"""
Multi-Factor Authentication (MFA) Module
Implements TOTP (RFC 6238) with QR code generation and backup codes.
"""

import secrets
import time
import hmac
import hashlib
import base64
from typing import Tuple, List, Optional
import pyotp
import qrcode
from io import BytesIO
from PIL import Image


class MFA:
    """
    Multi-Factor Authentication using TOTP (Time-based One-Time Password).
    Implements RFC 6238.
    """
    
    def __init__(self, issuer: str = "CryptoVault", time_window: int = 30):
        """
        Initialize MFA system.
        
        Args:
            issuer: Issuer name for TOTP (appears in authenticator app)
            time_window: TOTP time window in seconds (default 30)
        """
        self.issuer = issuer
        self.time_window = time_window
        self.tolerance = 1  # Accept codes from ±1 time window
    
    def generate_secret(self) -> str:
        """
        Generate a new TOTP secret.
        
        Returns:
            Base32-encoded secret
        """
        # Generate 160-bit (20-byte) secret as per RFC 6238
        secret_bytes = secrets.token_bytes(20)
        return base64.b32encode(secret_bytes).decode('utf-8')
    
    def generate_totp(self, secret: str, timestamp: Optional[int] = None) -> str:
        """
        Generate TOTP code for given secret.
        
        Args:
            secret: Base32-encoded secret
            timestamp: Unix timestamp (default: current time)
            
        Returns:
            6-digit TOTP code
        """
        if timestamp is None:
            timestamp = int(time.time())
        
        # Calculate time counter
        time_counter = timestamp // self.time_window
        
        # Decode secret
        try:
            secret_bytes = base64.b32decode(secret.upper())
        except Exception:
            raise ValueError("Invalid secret format")
        
        # HMAC-SHA1 as per RFC 6238
        hmac_result = hmac.new(
            secret_bytes,
            time_counter.to_bytes(8, 'big'),
            hashlib.sha1
        ).digest()
        
        # Dynamic truncation (RFC 4226)
        offset = hmac_result[19] & 0x0F
        binary = (
            ((hmac_result[offset] & 0x7F) << 24) |
            ((hmac_result[offset + 1] & 0xFF) << 16) |
            ((hmac_result[offset + 2] & 0xFF) << 8) |
            (hmac_result[offset + 3] & 0xFF)
        )
        otp = binary % 1000000
        
        return f"{otp:06d}"
    
    def verify_totp(self, secret: str, code: str, timestamp: Optional[int] = None) -> bool:
        """
        Verify TOTP code with time-window tolerance.
        
        Args:
            secret: Base32-encoded secret
            code: 6-digit code to verify
            timestamp: Unix timestamp (default: current time)
            
        Returns:
            True if code is valid
        """
        if timestamp is None:
            timestamp = int(time.time())
        
        # Check current window and ±tolerance windows
        for i in range(-self.tolerance, self.tolerance + 1):
            window_time = timestamp + (i * self.time_window)
            expected_code = self.generate_totp(secret, window_time)
            
            # Constant-time comparison
            if hmac.compare_digest(code, expected_code):
                return True
        
        return False
    
    def generate_qr_code(self, username: str, secret: str) -> Image.Image:
        """
        Generate QR code for TOTP setup.
        
        Args:
            username: Username
            secret: Base32-encoded secret
            
        Returns:
            PIL Image of QR code
        """
        # TOTP URI format: otpauth://totp/Issuer:Username?secret=SECRET&issuer=Issuer
        uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=username,
            issuer_name=self.issuer
        )
        
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        return img
    
    def generate_qr_code_bytes(self, username: str, secret: str) -> bytes:
        """
        Generate QR code as PNG bytes.
        
        Args:
            username: Username
            secret: Base32-encoded secret
            
        Returns:
            PNG image bytes
        """
        img = self.generate_qr_code(username, secret)
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        return buffer.getvalue()
    
    def generate_backup_codes(self, count: int = 10) -> List[str]:
        """
        Generate backup codes for MFA recovery.
        
        Args:
            count: Number of backup codes to generate
            
        Returns:
            List of backup codes (8-digit codes)
        """
        codes = []
        for _ in range(count):
            # Generate 8-digit code
            code = f"{secrets.randbelow(100000000):08d}"
            codes.append(code)
        return codes
    
    def hash_backup_code(self, code: str) -> str:
        """
        Hash a backup code for secure storage.
        
        Args:
            code: Plaintext backup code
            
        Returns:
            SHA-256 hash of code
        """
        return hashlib.sha256(code.encode('utf-8')).hexdigest()
    
    def verify_backup_code(self, code: str, hashed_codes: dict) -> Tuple[bool, Optional[str]]:
        """
        Verify backup code and mark as used.
        
        Args:
            code: Plaintext backup code
            hashed_codes: Dictionary mapping hashed codes to used status
            
        Returns:
            Tuple of (is_valid, hashed_code_key)
        """
        code_hash = self.hash_backup_code(code)
        
        if code_hash in hashed_codes:
            if not hashed_codes[code_hash]:  # Not used yet
                hashed_codes[code_hash] = True  # Mark as used
                return (True, code_hash)
        
        return (False, None)

