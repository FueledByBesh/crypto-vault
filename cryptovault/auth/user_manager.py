"""
User Management and Authentication
Handles user registration, login, password hashing, and session management.
"""

import secrets
import time
import hmac
import hashlib
from typing import Optional, Dict, Tuple
from dataclasses import dataclass, field
from cryptovault.auth.password_validator import PasswordValidator

try:
    import argon2
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False
    try:
        import bcrypt
        BCRYPT_AVAILABLE = True
    except ImportError:
        BCRYPT_AVAILABLE = False


@dataclass
class User:
    """User data structure."""
    username: str
    password_hash: str
    salt: bytes
    created_at: float
    failed_login_attempts: int = 0
    last_failed_login: float = 0.0
    locked_until: float = 0.0
    totp_secret: Optional[str] = None
    backup_codes: Dict[str, bool] = field(default_factory=dict)  # code -> used
    mfa_enabled: bool = False


class UserManager:
    """
    Manages user registration, authentication, and sessions.
    Uses Argon2id (preferred) or bcrypt for password hashing.
    """
    
    def __init__(self, use_argon2: bool = True, rate_limit_window: int = 300,
                 max_attempts: int = 5, lockout_duration: int = 900):
        """
        Initialize user manager.
        
        Args:
            use_argon2: Use Argon2id if available, else bcrypt
            rate_limit_window: Rate limit window in seconds (default 5 min)
            max_attempts: Max failed login attempts before lockout
            lockout_duration: Lockout duration in seconds (default 15 min)
        """
        self.users: Dict[str, User] = {}
        self.sessions: Dict[str, Dict] = {}  # token -> session_data
        self.password_validator = PasswordValidator()
        self.use_argon2 = use_argon2 and ARGON2_AVAILABLE
        self.rate_limit_window = rate_limit_window
        self.max_attempts = max_attempts
        self.lockout_duration = lockout_duration
        
        # Session secret for HMAC (should be loaded from secure config in production)
        self.session_secret = secrets.token_bytes(32)
    
    def register_user(self, username: str, password: str) -> Tuple[bool, str]:
        """
        Register a new user.
        
        Args:
            username: Username
            password: Plaintext password
            
        Returns:
            Tuple of (success, message)
        """
        if not username or not password:
            return (False, "Username and password are required")
        
        if username in self.users:
            return (False, "Username already exists")
        
        # Validate password strength
        is_valid, error_msg = self.password_validator.validate(password)
        if not is_valid:
            return (False, error_msg)
        
        # Generate CSPRNG salt
        salt = secrets.token_bytes(16)
        
        # Hash password
        if self.use_argon2:
            password_hash = argon2.PasswordHasher().hash(password)
        else:
            if not BCRYPT_AVAILABLE:
                return (False, "No password hashing library available")
            password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        # Create user
        user = User(
            username=username,
            password_hash=password_hash,
            salt=salt,
            created_at=time.time()
        )
        self.users[username] = user
        
        return (True, "User registered successfully")
    
    def verify_password(self, password: str, user: User) -> bool:
        """
        Verify password using constant-time comparison.
        
        Args:
            password: Plaintext password
            user: User object
            
        Returns:
            True if password is correct
        """
        try:
            if self.use_argon2:
                argon2.PasswordHasher().verify(user.password_hash, password)
                return True
            else:
                if not BCRYPT_AVAILABLE:
                    return False
                return bcrypt.checkpw(
                    password.encode('utf-8'),
                    user.password_hash.encode('utf-8')
                )
        except (argon2.exceptions.VerifyMismatchError, ValueError):
            return False
    
    def _check_rate_limit(self, username: str) -> Tuple[bool, str]:
        """
        Check if user is rate limited.
        
        Args:
            username: Username to check
            
        Returns:
            Tuple of (allowed, message)
        """
        if username not in self.users:
            return (True, "")  # User doesn't exist, but don't reveal this
        
        user = self.users[username]
        current_time = time.time()
        
        # Check if account is locked
        if user.locked_until > current_time:
            remaining = int(user.locked_until - current_time)
            return (False, f"Account locked. Try again in {remaining} seconds.")
        
        # Reset lockout if expired
        if user.locked_until > 0 and user.locked_until <= current_time:
            user.locked_until = 0.0
            user.failed_login_attempts = 0
        
        # Check rate limiting (failed attempts in window)
        if user.failed_login_attempts >= self.max_attempts:
            # Lock account
            user.locked_until = current_time + self.lockout_duration
            return (False, f"Too many failed attempts. Account locked for {self.lockout_duration // 60} minutes.")
        
        # Reset attempts if outside window
        if current_time - user.last_failed_login > self.rate_limit_window:
            user.failed_login_attempts = 0
        
        return (True, "")
    
    def login(self, username: str, password: str) -> Tuple[bool, Optional[str], str]:
        """
        Authenticate user and create session.
        
        Args:
            username: Username
            password: Plaintext password
            
        Returns:
            Tuple of (success, session_token, message)
        """
        # Check rate limiting
        allowed, rate_limit_msg = self._check_rate_limit(username)
        if not allowed:
            return (False, None, rate_limit_msg)
        
        # Check if user exists
        if username not in self.users:
            # Don't reveal if user exists (constant-time delay)
            time.sleep(0.1)  # Small delay to prevent timing attacks
            return (False, None, "Invalid username or password")
        
        user = self.users[username]
        
        # Verify password (constant-time)
        if not self.verify_password(password, user):
            user.failed_login_attempts += 1
            user.last_failed_login = time.time()
            return (False, None, "Invalid username or password")
        
        # Reset failed attempts on successful login
        user.failed_login_attempts = 0
        user.locked_until = 0.0
        
        # Generate session token using HMAC-SHA256
        session_data = {
            'username': username,
            'created_at': time.time(),
            'expires_at': time.time() + 3600  # 1 hour session
        }
        
        # Create HMAC token
        token_data = f"{username}:{session_data['created_at']}:{session_data['expires_at']}"
        token = hmac.new(
            self.session_secret,
            token_data.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        self.sessions[token] = session_data
        
        return (True, token, "Login successful")
    
    def create_session(self, username: str) -> Tuple[bool, Optional[str], str]:
        """
        Create session for authenticated user (used after MFA verification).
        
        Args:
            username: Username
            
        Returns:
            Tuple of (success, session_token, message)
        """
        if username not in self.users:
            return (False, None, "User not found")
        
        user = self.users[username]
        
        # Reset failed attempts
        user.failed_login_attempts = 0
        user.locked_until = 0.0
        
        # Generate session token using HMAC-SHA256
        session_data = {
            'username': username,
            'created_at': time.time(),
            'expires_at': time.time() + 3600  # 1 hour session
        }
        
        # Create HMAC token
        token_data = f"{username}:{session_data['created_at']}:{session_data['expires_at']}"
        token = hmac.new(
            self.session_secret,
            token_data.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        self.sessions[token] = session_data
        
        return (True, token, "Session created")
    
    def verify_session(self, token: str) -> Tuple[bool, Optional[str]]:
        """
        Verify session token.
        
        Args:
            token: Session token
            
        Returns:
            Tuple of (is_valid, username)
        """
        if token not in self.sessions:
            return (False, None)
        
        session = self.sessions[token]
        current_time = time.time()
        
        # Check expiration
        if current_time > session['expires_at']:
            del self.sessions[token]
            return (False, None)
        
        return (True, session['username'])
    
    def logout(self, token: str) -> bool:
        """
        Invalidate session token.
        
        Args:
            token: Session token
            
        Returns:
            True if session was invalidated
        """
        if token in self.sessions:
            del self.sessions[token]
            return True
        return False
    
    def get_user(self, username: str) -> Optional[User]:
        """Get user by username."""
        return self.users.get(username)
    
    def enable_mfa(self, username: str, totp_secret: str, backup_codes: list) -> bool:
        """
        Enable MFA for user.
        
        Args:
            username: Username
            totp_secret: TOTP secret
            backup_codes: List of backup codes
            
        Returns:
            True if successful
        """
        if username not in self.users:
            return False
        
        user = self.users[username]
        user.totp_secret = totp_secret
        user.backup_codes = {code: False for code in backup_codes}
        user.mfa_enabled = True
        return True

