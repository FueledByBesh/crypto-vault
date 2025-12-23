"""
Unit tests for Authentication Module
"""

import pytest
import time
from cryptovault.auth.user_manager import UserManager
from cryptovault.auth.mfa import MFA
from cryptovault.auth.password_validator import PasswordValidator


class TestPasswordValidator:
    """Test password validation."""
    
    def test_valid_password(self):
        """Test valid password."""
        validator = PasswordValidator()
        is_valid, msg = validator.validate("SecurePass123!")
        assert is_valid
    
    def test_short_password(self):
        """Test short password rejection."""
        validator = PasswordValidator(min_length=12)
        is_valid, msg = validator.validate("Short1!")
        assert not is_valid
    
    def test_missing_requirements(self):
        """Test missing character requirements."""
        validator = PasswordValidator()
        is_valid, msg = validator.validate("nouppercase123!")
        assert not is_valid


class TestUserManager:
    """Test user management."""
    
    def test_register_user(self):
        """Test user registration."""
        manager = UserManager()
        success, msg = manager.register_user("testuser", "SecurePass123!")
        assert success
        assert "testuser" in manager.users
    
    def test_duplicate_registration(self):
        """Test duplicate registration rejection."""
        manager = UserManager()
        manager.register_user("testuser", "SecurePass123!")
        success, msg = manager.register_user("testuser", "AnotherPass123!")
        assert not success
    
    def test_login_success(self):
        """Test successful login."""
        manager = UserManager()
        manager.register_user("testuser", "SecurePass123!")
        success, token, msg = manager.login("testuser", "SecurePass123!")
        assert success
        assert token is not None
    
    def test_login_failure(self):
        """Test failed login."""
        manager = UserManager()
        manager.register_user("testuser", "SecurePass123!")
        success, token, msg = manager.login("testuser", "WrongPassword")
        assert not success
        assert token is None
    
    def test_session_verification(self):
        """Test session token verification."""
        manager = UserManager()
        manager.register_user("testuser", "SecurePass123!")
        success, token, _ = manager.login("testuser", "SecurePass123!")
        
        is_valid, username = manager.verify_session(token)
        assert is_valid
        assert username == "testuser"
    
    def test_rate_limiting(self):
        """Test rate limiting on failed logins."""
        manager = UserManager(max_attempts=3)
        manager.register_user("testuser", "SecurePass123!")
        
        # Make failed attempts
        for _ in range(3):
            manager.login("testuser", "WrongPassword")
        
        # Next attempt should be rate limited
        success, token, msg = manager.login("testuser", "SecurePass123!")
        assert not success


class TestMFA:
    """Test MFA implementation."""
    
    def test_totp_generation(self):
        """Test TOTP code generation."""
        mfa = MFA()
        secret = mfa.generate_secret()
        code = mfa.generate_totp(secret)
        assert len(code) == 6
        assert code.isdigit()
    
    def test_totp_verification(self):
        """Test TOTP code verification."""
        mfa = MFA()
        secret = mfa.generate_secret()
        code = mfa.generate_totp(secret)
        
        is_valid = mfa.verify_totp(secret, code)
        assert is_valid
    
    def test_totp_time_window(self):
        """Test TOTP time window tolerance."""
        mfa = MFA()
        secret = mfa.generate_secret()
        timestamp = int(time.time())
        
        # Generate code for current window
        code = mfa.generate_totp(secret, timestamp)
        
        # Should verify in same window
        is_valid = mfa.verify_totp(secret, code, timestamp)
        assert is_valid
    
    def test_backup_codes(self):
        """Test backup code generation and verification."""
        mfa = MFA()
        codes = mfa.generate_backup_codes(count=10)
        assert len(codes) == 10
        
        # Verify backup code
        hashed_codes = {mfa.hash_backup_code(code): False for code in codes}
        is_valid, _ = mfa.verify_backup_code(codes[0], hashed_codes)
        assert is_valid
        
        # Verify used code cannot be reused
        is_valid2, _ = mfa.verify_backup_code(codes[0], hashed_codes)
        assert not is_valid2

