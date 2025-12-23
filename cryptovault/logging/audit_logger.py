"""
Audit Logging Module
Securely logs all security-sensitive actions with hashed sensitive fields.
"""

import time
import hashlib
import json
from typing import Optional, Dict
from pathlib import Path
from cryptovault.core.sha256_simplified import SHA256Simplified


class AuditLogger:
    """
    Secure audit logger that hashes sensitive information.
    Logs security-sensitive actions for compliance and forensics.
    """
    
    def __init__(self, log_file: str = "audit.log"):
        """
        Initialize audit logger.
        
        Args:
            log_file: Path to log file
        """
        self.log_file = Path(log_file)
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
    
    def _hash_sensitive(self, value: str) -> str:
        """
        Hash sensitive value for logging.
        
        Args:
            value: Sensitive value to hash
            
        Returns:
            SHA-256 hash (hex)
        """
        return SHA256Simplified.hash(value.encode('utf-8')).hex()
    
    def _create_log_entry(self, event_type: str, username: Optional[str] = None,
                          ip_address: Optional[str] = None, file_path: Optional[str] = None,
                          success: bool = True, details: Optional[Dict] = None) -> dict:
        """
        Create log entry with hashed sensitive fields.
        
        Args:
            event_type: Type of event (e.g., "login", "file_encrypt", "file_decrypt")
            username: Username (will be hashed)
            ip_address: IP address (will be hashed)
            file_path: File path (will be hashed)
            success: Whether action was successful
            details: Additional details (non-sensitive)
            
        Returns:
            Log entry dictionary
        """
        entry = {
            'timestamp': time.time(),
            'event_type': event_type,
            'success': success,
            'details': details or {}
        }
        
        # Hash sensitive fields
        if username:
            entry['username_hash'] = self._hash_sensitive(username)
        
        if ip_address:
            entry['ip_hash'] = self._hash_sensitive(ip_address)
        
        if file_path:
            entry['file_hash'] = self._hash_sensitive(file_path)
        
        return entry
    
    def log(self, event_type: str, username: Optional[str] = None,
            ip_address: Optional[str] = None, file_path: Optional[str] = None,
            success: bool = True, details: Optional[Dict] = None):
        """
        Log security event.
        
        Args:
            event_type: Type of event
            username: Username (will be hashed)
            ip_address: IP address (will be hashed)
            file_path: File path (will be hashed)
            success: Whether action was successful
            details: Additional details
        """
        entry = self._create_log_entry(
            event_type, username, ip_address, file_path, success, details
        )
        
        # Write to log file (append mode)
        with open(self.log_file, 'a') as f:
            f.write(json.dumps(entry) + '\n')
    
    def log_login_attempt(self, username: str, ip_address: str, success: bool,
                          mfa_used: bool = False):
        """
        Log login attempt.
        
        Args:
            username: Username
            ip_address: IP address
            success: Whether login was successful
            mfa_used: Whether MFA was used
        """
        self.log(
            event_type="login_attempt",
            username=username,
            ip_address=ip_address,
            success=success,
            details={'mfa_used': mfa_used}
        )
    
    def log_file_encryption(self, username: str, file_path: str, success: bool,
                            algorithm: Optional[str] = None):
        """
        Log file encryption event.
        
        Args:
            username: Username
            file_path: Path to encrypted file
            success: Whether encryption was successful
            algorithm: Encryption algorithm used
        """
        self.log(
            event_type="file_encrypt",
            username=username,
            file_path=file_path,
            success=success,
            details={'algorithm': algorithm} if algorithm else None
        )
    
    def log_file_decryption(self, username: str, file_path: str, success: bool,
                            integrity_verified: bool = False):
        """
        Log file decryption event.
        
        Args:
            username: Username
            file_path: Path to decrypted file
            success: Whether decryption was successful
            integrity_verified: Whether integrity was verified
        """
        self.log(
            event_type="file_decrypt",
            username=username,
            file_path=file_path,
            success=success,
            details={'integrity_verified': integrity_verified}
        )
    
    def log_messaging_event(self, username: str, action: str, success: bool,
                            peer: Optional[str] = None):
        """
        Log messaging event.
        
        Args:
            username: Username
            action: Action type (e.g., "send", "receive")
            success: Whether action was successful
            peer: Peer username (will be hashed)
        """
        details = {'action': action}
        if peer:
            details['peer_hash'] = self._hash_sensitive(peer)
        
        self.log(
            event_type="messaging",
            username=username,
            success=success,
            details=details
        )
    
    def log_mfa_setup(self, username: str, success: bool):
        """
        Log MFA setup event.
        
        Args:
            username: Username
            success: Whether setup was successful
        """
        self.log(
            event_type="mfa_setup",
            username=username,
            success=success
        )
    
    def get_recent_logs(self, limit: int = 100) -> list:
        """
        Get recent log entries.
        
        Args:
            limit: Maximum number of entries to return
            
        Returns:
            List of log entries
        """
        if not self.log_file.exists():
            return []
        
        entries = []
        with open(self.log_file, 'r') as f:
            lines = f.readlines()
            for line in lines[-limit:]:
                try:
                    entry = json.loads(line.strip())
                    entries.append(entry)
                except json.JSONDecodeError:
                    continue
        
        return entries

