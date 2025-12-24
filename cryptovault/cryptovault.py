"""
CryptoVault - Main Integration Layer
Connects all modules into a unified cryptographic security suite.
"""

from math import log
from typing import Optional, Tuple, Dict, List
import time
from cryptovault.auth.user_manager import UserManager
from cryptovault.auth.mfa import MFA
from cryptovault.messaging.secure_messenger import SecureMessenger
from cryptovault.file_encryption.file_encryptor import FileEncryptor
from cryptovault.blockchain.blockchain import Blockchain
from cryptovault.core.database import SimpleDatabase
from cryptovault.logging.audit_logger import AuditLogger


class CryptoVault:
    """
    Main CryptoVault system integrating all modules.
    """
    
    def __init__(self, audit_log_file: str = "audit.log", blockchain_difficulty: int = 2, blockchain_file: str = "blockchain.json"):
        """
        Initialize CryptoVault system.
        
        Args:
            audit_log_file: Path to audit log file
            blockchain_difficulty: Blockchain PoW difficulty
            blockchain_file: Path to blockchain persistence file
        """
        # Initialize modules
        self.user_manager = UserManager()
        self.mfa = MFA()
        self.audit_logger = AuditLogger(audit_log_file)
        self.blockchain = Blockchain(blockchain_difficulty, blockchain_file)
        
        # Database for persistence
        self.db = SimpleDatabase("data/cryptovault.json")
        
        # Per-user messaging sessions: {username: SecureMessenger}
        self.messaging_sessions: Dict[str, SecureMessenger] = {}
        
        # Message store: {receiver: [(sender, encrypted_message, signature, timestamp), ...]}
        self.message_store: Dict[str, List[Tuple[str, bytes, Optional[bytes], float]]] = {}
        
        # Load persistent data
        self.load_persistent_data()
        
        # Per-user file encryptors (keyed by username)
        self.file_encryptors: Dict[str, FileEncryptor] = {}
    
    def load_persistent_data(self):
        """Load persistent data from database."""
        try:
            # Load message store
            message_data = self.db.get('messages', {})
            for receiver, messages in message_data.items():
                self.message_store[receiver] = []
                for msg_data in messages:
                    message_tuple = (
                        msg_data['sender'],
                        bytes.fromhex(msg_data['encrypted_message']),
                        bytes.fromhex(msg_data['signature']) if msg_data['signature'] else None,
                        msg_data['timestamp']
                    )
                    self.message_store[receiver].append(message_tuple)
        except Exception as e:
            print(f"Error loading persistent data: {e}")
    
    def save_persistent_data(self):
        """Save persistent data to database."""
        try:
            # Save message store
            message_data = {}
            for receiver, messages in self.message_store.items():
                message_data[receiver] = []
                for sender, encrypted_msg, signature, timestamp in messages:
                    msg_data = {
                        'sender': sender,
                        'encrypted_message': encrypted_msg.hex(),
                        'signature': signature.hex() if signature else None,
                        'timestamp': timestamp
                    }
                    message_data[receiver].append(msg_data)
            
            self.db.set('messages', message_data)
        except Exception as e:
            print(f"Error saving persistent data: {e}")
    
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
        Initialize messaging for user.
        
        Args:
            username: Username
            
        Returns:
            Public key bytes
        """
        if username not in self.messaging_sessions:
            messenger = SecureMessenger()
            pub, _ = messenger.establish_session(None)
            self.messaging_sessions[username] = messenger
        else:
            messenger = self.messaging_sessions[username]
            pub = messenger.key_exchange.serialize_public_key(messenger.public_key)
        return pub
    
    def establish_messaging_session(self, username: str, peer_public_key: bytes) -> bytes:
        """
        Establish messaging session with peer.
        
        Args:
            username: Username
            peer_public_key: Peer's ECDH public key
            
        Returns:
            Our public key
        """
        if username not in self.messaging_sessions:
            raise ValueError("Messaging not initialized for user")
        
        messenger = self.messaging_sessions[username]
        our_pub, _ = messenger.establish_session(peer_public_key)
        return our_pub
    
    def send_message(self, sender_username: str, receiver_username: str, message: str, sign: bool = True) -> bool:
        """
        Send encrypted message to another user.
        
        Args:
            sender_username: Sender username
            receiver_username: Receiver username
            message: Plaintext message
            sign: Whether to sign message
            
        Returns:
            True if sent successfully
        """
        if sender_username not in self.messaging_sessions:
            raise ValueError("Messaging session not established")
        
        messenger = self.messaging_sessions[sender_username]
        encrypted, signature = messenger.send_message(message, sign)
        
        # Store message for receiver
        if receiver_username not in self.message_store:
            self.message_store[receiver_username] = []
        self.message_store[receiver_username].append((sender_username, encrypted, signature, time.time()))
        
        # Save to persistent storage
        self.save_persistent_data()
        
        # Log messaging event
        self.audit_logger.log_messaging_event(
            username=sender_username,
            action="send",
            success=True
        )
        
        # Create blockchain transaction
        tx = self.blockchain.create_transaction(
            action="send_message",
            user=sender_username,
            data=f"Message sent to {receiver_username} (length: {len(message)})"
        )
        self.blockchain.add_transaction(tx)
        
        return True
    
    def get_messages(self, username: str) -> List[Tuple[str, str, bool, float]]:
        """
        Get and decrypt pending messages for user.
        
        Args:
            username: Username
            
        Returns:
            List of (sender, message, signature_valid, timestamp)
        """
        if username not in self.message_store:
            return []
        
        messages = []
        remaining_messages = []
        
        for sender, encrypted, signature, timestamp in self.message_store[username]:
            try:
                if username not in self.messaging_sessions:
                    # Cannot decrypt without session
                    remaining_messages.append((sender, encrypted, signature, timestamp))
                    continue
                
                messenger = self.messaging_sessions[username]
                message, sig_valid = messenger.receive_message(encrypted, signature)
                messages.append((sender, message, sig_valid, timestamp))
                
                # Log messaging event
                self.audit_logger.log_messaging_event(
                    username=username,
                    action="receive",
                    success=True
                )
            except Exception as e:
                # Keep message if decryption fails
                remaining_messages.append((sender, encrypted, signature, timestamp))
        
        # Update message store with remaining messages
        self.message_store[username] = remaining_messages
        
        return messages
    
    def get_users_for_messaging(self, current_username: str) -> List[str]:
        """
        Get list of users available for messaging (excluding current user).
        
        Args:
            current_username: Current user
            
        Returns:
            List of usernames
        """
        users = self.user_manager.get_all_users()
        return [u for u in users if u != current_username]
    
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

