"""
Integration tests for CryptoVault system
"""

import pytest
import tempfile
import os
from cryptovault.cryptovault import CryptoVault


class TestCryptoVaultIntegration:
    """Integration tests for complete CryptoVault system."""
    
    def test_user_registration_and_login(self):
        """Test user registration and login flow."""
        vault = CryptoVault()
        
        # Register user
        success, msg = vault.register_user("alice", "SecurePass123!")
        assert success
        
        # Login
        success, token, msg = vault.login("alice", "SecurePass123!")
        assert success
        assert token is not None
        
        # Verify session
        is_valid, username = vault.verify_session(token)
        assert is_valid
        assert username == "alice"
    
    def test_mfa_setup(self):
        """Test MFA setup flow."""
        vault = CryptoVault()
        vault.register_user("alice", "SecurePass123!")
        
        success, secret, backup_codes, qr_code = vault.setup_mfa("alice", "SecurePass123!")
        assert success
        assert secret is not None
        assert backup_codes is not None
        assert qr_code is not None
    
    def test_file_encryption_decryption(self):
        """Test file encryption and decryption."""
        vault = CryptoVault()
        vault.register_user("alice", "SecurePass123!")
        vault.login("alice", "SecurePass123!")
        
        # Create test file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("This is a test file for encryption.")
            input_path = f.name
        
        try:
            output_encrypted = input_path + ".encrypted"
            output_decrypted = input_path + ".decrypted"
            
            # Encrypt
            metadata = vault.encrypt_file("alice", input_path, output_encrypted, "filepass123")
            assert os.path.exists(output_encrypted)
            
            # Decrypt
            result = vault.decrypt_file("alice", output_encrypted, output_decrypted, "filepass123")
            assert result['hash_verified']
            assert result['hmac_verified']
            
            # Verify content
            with open(output_decrypted, 'r') as f:
                content = f.read()
                assert content == "This is a test file for encryption."
            
            # Cleanup
            os.unlink(output_encrypted)
            os.unlink(output_decrypted)
        finally:
            os.unlink(input_path)
    
    def test_secure_messaging(self):
        """Test secure messaging between users."""
        vault = CryptoVault()
        
        # Register and login users
        vault.register_user("alice", "SecurePass123!")
        vault.register_user("bob", "SecurePass456!")
        
        vault.login("alice", "SecurePass123!")
        vault.login("bob", "SecurePass456!")
        
        # Initialize messaging for both
        alice_pub = vault.initialize_messaging("alice")
        bob_pub = vault.initialize_messaging("bob")
        
        # Establish sessions
        alice_pub2, alice_verif = vault.establish_messaging_session("alice", bob_pub)
        bob_pub2, bob_verif = vault.establish_messaging_session("bob", alice_pub, alice_verif)
        
        # Send message
        message = "Hello, Bob! This is a secret message."
        encrypted, signature = vault.send_message("alice", message)
        
        # Receive message
        decrypted, sig_valid = vault.receive_message("bob", encrypted, signature)
        assert decrypted == message
        assert sig_valid
    
    def test_blockchain_integrity(self):
        """Test blockchain validation."""
        vault = CryptoVault()
        
        # Perform some actions
        vault.register_user("alice", "SecurePass123!")
        vault.login("alice", "SecurePass123!")
        
        # Validate blockchain
        is_valid, error = vault.validate_blockchain()
        assert is_valid, error
    
    def test_audit_logging(self):
        """Test audit logging."""
        vault = CryptoVault(audit_log_file="test_audit.log")
        
        vault.register_user("alice", "SecurePass123!")
        vault.login("alice", "SecurePass123!")
        
        # Get recent logs
        logs = vault.get_recent_audit_logs(10)
        assert len(logs) > 0
        
        # Check log entries
        event_types = [log['event_type'] for log in logs]
        assert "user_registration" in event_types
        assert "login_attempt" in event_types
        
        # Cleanup
        if os.path.exists("test_audit.log"):
            os.unlink("test_audit.log")

