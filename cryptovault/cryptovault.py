"""
CryptoVault - Main Integration Layer
Connects all modules into a unified cryptographic security suite.
"""

from math import log
from typing import Optional, Tuple, Dict
from cryptovault.auth.user_manager import UserManager
from cryptovault.auth.mfa import MFA
from cryptovault.messaging.secure_messenger import SecureMessenger
from cryptovault.file_encryption.file_encryptor import FileEncryptor
from cryptovault.blockchain.blockchain import Blockchain
from cryptovault.logging.audit_logger import AuditLogger


class CryptoVault:
    """
    Main CryptoVault system integrating all modules.
    """
    
    def __init__(self, audit_log_file: str = "audit.log", blockchain_difficulty: int = 2):
        """
        Initialize CryptoVault system.
        
        Args:
            audit_log_file: Path to audit log file
            blockchain_difficulty: Blockchain PoW difficulty
        """
        # Initialize modules
        self.user_manager = UserManager()
        self.mfa = MFA()
        self.audit_logger = AuditLogger(audit_log_file)
        self.blockchain = Blockchain(blockchain_difficulty)
        
        # Per-user messaging sessions
        self.messaging_sessions: Dict[str, SecureMessenger] = {}
        
        # Per-user file encryptors (keyed by username)
        self.file_encryptors: Dict[str, FileEncryptor] = {}
    
    # ==================== Authentication ====================
    
    def register_user(self, username: str, password: str) -> Tuple[bool, str]:
        """
        Register a new user.
        
        Args:
            username: Username
            password: Password
            
        Returns:
            Tuple of (success, message)
        """
        success, message = self.user_manager.register_user(username, password)
        print("Register user:", success, message)

        if success:
            # Log registration
            self.audit_logger.log(
                event_type="user_registration",
                username=username,
                success=True
            )
            print("Audit log created for user registration.")
            
            # Create blockchain transaction
            tx = self.blockchain.create_transaction(
                action="user_registration",
                user=username,
                data=f"User {username} registered"
            )
            self.blockchain.add_transaction(tx)
            self.blockchain.mine_pending_transactions()
            print("Blockchain transaction created for user registration.")
        
        return (success, message)
    
    def login(self, username: str, password: str, 
              ip_address: str = "unknown") -> Tuple[bool, Optional[str], str]:
        """
        Authenticate user.
        
        Args:
            username: Username
            password: Password
            ip_address: Client IP address
            
        Returns:
            Tuple of (success, session_token, message)
        """
        success, token, message = self.user_manager.login(username, password)
        
        # Log login attempt
        self.audit_logger.log_login_attempt(
            username=username,
            ip_address=ip_address,
            success=success
        )
        
        if success:
            # Create blockchain transaction
            tx = self.blockchain.create_transaction(
                action="login",
                user=username,
                data=f"User {username} logged in from {ip_address}"
            )
            self.blockchain.add_transaction(tx)
            self.blockchain.mine_pending_transactions()
        
        return (success, token, message)
    
    def setup_mfa(self, username: str, password: str) -> Tuple[bool, Optional[str], Optional[list], Optional[bytes]]:
        """
        Setup MFA for user.
        
        Args:
            username: Username
            password: Password for verification
            
        Returns:
            Tuple of (success, totp_secret, backup_codes, qr_code_bytes)
        """
        # Verify password first
        user = self.user_manager.get_user(username)
        if not user or not self.user_manager.verify_password(password, user):
            return (False, None, None, None)
        
        # Generate TOTP secret
        totp_secret = self.mfa.generate_secret()
        
        # Generate backup codes
        backup_codes = self.mfa.generate_backup_codes()
        
        # Hash backup codes for storage
        hashed_codes = {
            self.mfa.hash_backup_code(code): False
            for code in backup_codes
        }
        
        # Enable MFA
        self.user_manager.enable_mfa(username, totp_secret, list(hashed_codes.keys()))
        
        # Generate QR code
        qr_code = self.mfa.generate_qr_code_bytes(username, totp_secret)
        
        # Log MFA setup
        self.audit_logger.log_mfa_setup(username, True)
        
        return (True, totp_secret, backup_codes, qr_code)
    
    def verify_mfa(self, username: str, code: str) -> bool:
        """
        Verify MFA code.
        
        Args:
            username: Username
            code: TOTP code or backup code
            
        Returns:
            True if code is valid
        """
        user = self.user_manager.get_user(username)
        if not user or not user.mfa_enabled:
            return False
        
        # Try TOTP first
        if user.totp_secret:
            if self.mfa.verify_totp(user.totp_secret, code):
                return True
        
        # Try backup code
        is_valid, code_hash = self.mfa.verify_backup_code(code, user.backup_codes)
        if is_valid:
            # Update user's backup codes
            user.backup_codes[code_hash] = True
            return True
        
        return False
    
    def verify_session(self, token: str) -> Tuple[bool, Optional[str]]:
        """
        Verify session token.
        
        Args:
            token: Session token
            
        Returns:
            Tuple of (is_valid, username)
        """
        return self.user_manager.verify_session(token)
    
    # ==================== Secure Messaging ====================
    
    def initialize_messaging(self, username: str) -> bytes:
        """
        Initialize secure messaging session for user.
        
        Args:
            username: Username
            
        Returns:
            Public key bytes to share with peer
        """
        messenger = SecureMessenger()
        public_key = messenger.initialize_session()
        self.messaging_sessions[username] = messenger
        return public_key
    
    def establish_messaging_session(self, username: str, peer_public_key: bytes,
                                    peer_verification_key: Optional[bytes] = None) -> Tuple[bytes, Optional[bytes]]:
        """
        Establish messaging session with peer.
        
        Args:
            username: Username
            peer_public_key: Peer's ECDH public key
            peer_verification_key: Peer's signature verification key
            
        Returns:
            Tuple of (our_public_key, our_verification_key)
        """
        if username not in self.messaging_sessions:
            self.initialize_messaging(username)
        
        messenger = self.messaging_sessions[username]
        return messenger.establish_session(peer_public_key, peer_verification_key)
    
    def send_message(self, username: str, message: str, sign: bool = True) -> Tuple[bytes, Optional[bytes]]:
        """
        Send encrypted message.
        
        Args:
            username: Sender username
            message: Plaintext message
            sign: Whether to sign message
            
        Returns:
            Tuple of (encrypted_message, signature)
        """
        if username not in self.messaging_sessions:
            raise ValueError("Messaging session not initialized")
        
        messenger = self.messaging_sessions[username]
        encrypted, signature = messenger.send_message(message, sign)
        
        # Log messaging event
        self.audit_logger.log_messaging_event(
            username=username,
            action="send",
            success=True
        )
        
        # Create blockchain transaction
        tx = self.blockchain.create_transaction(
            action="send_message",
            user=username,
            data=f"Message sent (length: {len(message)})"
        )
        self.blockchain.add_transaction(tx)
        
        return (encrypted, signature)
    
    def receive_message(self, username: str, encrypted_message: bytes,
                       signature: Optional[bytes] = None) -> Tuple[str, bool]:
        """
        Receive and decrypt message.
        
        Args:
            username: Receiver username
            encrypted_message: Encrypted message
            signature: Optional signature
            
        Returns:
            Tuple of (decrypted_message, signature_valid)
        """
        if username not in self.messaging_sessions:
            raise ValueError("Messaging session not established")
        
        messenger = self.messaging_sessions[username]
        message, sig_valid = messenger.receive_message(encrypted_message, signature)
        
        # Log messaging event
        self.audit_logger.log_messaging_event(
            username=username,
            action="receive",
            success=True
        )
        
        return (message, sig_valid)
    
    # ==================== File Encryption ====================
    
    def encrypt_file(self, username: str, input_path: str, output_path: str,
                    password: str, algorithm: str = "AES-GCM") -> Dict:
        """
        Encrypt file.
        
        Args:
            username: Username
            input_path: Input file path
            output_path: Output encrypted file path
            password: Encryption password
            algorithm: "AES-GCM" or "ChaCha20-Poly1305"
            
        Returns:
            Dictionary with encryption metadata
        """
        # Get or create file encryptor for user
        if username not in self.file_encryptors:
            self.file_encryptors[username] = FileEncryptor(algorithm=algorithm)
        
        encryptor = self.file_encryptors[username]
        metadata = encryptor.encrypt_file(input_path, output_path, password)
        
        # Log file encryption
        self.audit_logger.log_file_encryption(
            username=username,
            file_path=input_path,
            success=True,
            algorithm=algorithm
        )
        
        # Create blockchain transaction
        tx = self.blockchain.create_transaction(
            action="file_encrypt",
            user=username,
            data=f"File encrypted: {input_path}",
            metadata={'algorithm': algorithm, 'file_hash': metadata['file_hash']}
        )
        self.blockchain.add_transaction(tx)
        self.blockchain.mine_pending_transactions()
        
        return metadata
    
    def decrypt_file(self, username: str, input_path: str, output_path: str,
                    password: str) -> Dict:
        """
        Decrypt file.
        
        Args:
            username: Username
            input_path: Encrypted file path
            output_path: Decrypted file path
            password: Decryption password
            
        Returns:
            Dictionary with decryption metadata
        """
        # Get file encryptor (algorithm determined from file)
        if username not in self.file_encryptors:
            # Default to AES-GCM
            self.file_encryptors[username] = FileEncryptor(algorithm="AES-GCM")
        
        encryptor = self.file_encryptors[username]
        metadata = encryptor.decrypt_file(input_path, output_path, password)
        
        # Log file decryption
        self.audit_logger.log_file_decryption(
            username=username,
            file_path=input_path,
            success=metadata.get('hash_verified', False),
            integrity_verified=metadata.get('hmac_verified', False)
        )
        
        # Create blockchain transaction
        tx = self.blockchain.create_transaction(
            action="file_decrypt",
            user=username,
            data=f"File decrypted: {input_path}",
            metadata={'integrity_verified': metadata.get('hmac_verified', False)}
        )
        self.blockchain.add_transaction(tx)
        self.blockchain.mine_pending_transactions()
        
        return metadata
    
    # ==================== Blockchain & Audit ====================
    
    def get_blockchain_info(self) -> Dict:
        """Get blockchain information."""
        return self.blockchain.get_chain_info()
    
    def get_blockchain_logs(self) -> list:
        """Get blockchain logs (all blocks with transactions)."""
        return self.blockchain.get_chain_logs()
    
    def validate_blockchain(self) -> Tuple[bool, Optional[str]]:
        """Validate blockchain integrity."""
        return self.blockchain.validate_chain()
    
    def get_recent_audit_logs(self, limit: int = 100) -> list:
        """Get recent audit log entries."""
        return self.audit_logger.get_recent_logs(limit)

