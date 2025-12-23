"""
Password Strength Validation
Validates passwords according to security requirements.
"""

import re
from typing import Tuple


class PasswordValidator:
    """
    Validates password strength.
    """
    
    def __init__(self, min_length: int = 12, require_upper: bool = True,
                 require_lower: bool = True, require_digit: bool = True,
                 require_special: bool = True):
        """
        Initialize password validator.
        
        Args:
            min_length: Minimum password length
            require_upper: Require uppercase letters
            require_lower: Require lowercase letters
            require_digit: Require digits
            require_special: Require special characters
        """
        self.min_length = min_length
        self.require_upper = require_upper
        self.require_lower = require_lower
        self.require_digit = require_digit
        self.require_special = require_special
    
    def validate(self, password: str) -> Tuple[bool, str]:
        """
        Validate password strength.
        
        Args:
            password: Password to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if len(password) < self.min_length:
            return (False, f"Password must be at least {self.min_length} characters long")
        
        if self.require_upper and not re.search(r'[A-Z]', password):
            return (False, "Password must contain at least one uppercase letter")
        
        if self.require_lower and not re.search(r'[a-z]', password):
            return (False, "Password must contain at least one lowercase letter")
        
        if self.require_digit and not re.search(r'\d', password):
            return (False, "Password must contain at least one digit")
        
        if self.require_special and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return (False, "Password must contain at least one special character")
        
        # Check for common weak patterns
        if re.search(r'(.)\1{2,}', password):  # Same character repeated 3+ times
            return (False, "Password should not contain repeated characters")
        
        # Check for sequential patterns (simplified)
        if self._has_sequential_chars(password):
            return (False, "Password should not contain obvious sequential patterns")
        
        return (True, "Password is valid")
    
    def _has_sequential_chars(self, password: str) -> bool:
        """Check for obvious sequential patterns like 'abc' or '123'."""
        password_lower = password.lower()
        for i in range(len(password_lower) - 2):
            seq = password_lower[i:i+3]
            if (ord(seq[1]) == ord(seq[0]) + 1 and 
                ord(seq[2]) == ord(seq[1]) + 1):
                return True
        return False

