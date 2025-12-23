"""
Caesar Cipher Implementation FROM SCRATCH
Educational implementation for exam project.

This is a from-scratch implementation - no crypto libraries used.
"""

import string
from typing import Tuple, List


class CaesarCipher:
    """
    Caesar cipher implementation with frequency analysis attack.
    
    Security Note: This is for educational purposes only.
    Caesar cipher is NOT secure for real-world use.
    """
    
    def __init__(self, shift: int = 0):
        """
        Initialize Caesar cipher with a shift value.
        
        Args:
            shift: Number of positions to shift (0-25)
        """
        if not 0 <= shift <= 25:
            raise ValueError("Shift must be between 0 and 25")
        self.shift = shift
        self.alphabet = string.ascii_lowercase
        self.alphabet_upper = string.ascii_uppercase
    
    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt plaintext using Caesar cipher.
        
        Args:
            plaintext: Text to encrypt
            
        Returns:
            Encrypted ciphertext
        """
        result = []
        for char in plaintext:
            if char.islower():
                idx = (self.alphabet.index(char) + self.shift) % 26
                result.append(self.alphabet[idx])
            elif char.isupper():
                idx = (self.alphabet_upper.index(char) + self.shift) % 26
                result.append(self.alphabet_upper[idx])
            else:
                result.append(char)  # Non-alphabetic characters unchanged
        return ''.join(result)
    
    def decrypt(self, ciphertext: str) -> str:
        """
        Decrypt ciphertext using Caesar cipher.
        
        Args:
            ciphertext: Text to decrypt
            
        Returns:
            Decrypted plaintext
        """
        result = []
        for char in ciphertext:
            if char.islower():
                idx = (self.alphabet.index(char) - self.shift) % 26
                result.append(self.alphabet[idx])
            elif char.isupper():
                idx = (self.alphabet_upper.index(char) - self.shift) % 26
                result.append(self.alphabet_upper[idx])
            else:
                result.append(char)
        return ''.join(result)


class FrequencyAnalyzer:
    """
    Frequency analysis attack on Caesar cipher.
    Uses letter frequency statistics to break the cipher.
    """
    
    # English letter frequencies (approximate)
    ENGLISH_FREQUENCIES = {
        'e': 12.02, 't': 9.10, 'a': 8.12, 'o': 7.68, 'i': 7.31,
        'n': 6.95, 's': 6.28, 'r': 6.02, 'h': 5.92, 'd': 4.32,
        'l': 3.98, 'u': 2.88, 'c': 2.71, 'm': 2.61, 'f': 2.30,
        'y': 2.11, 'w': 2.09, 'g': 2.03, 'p': 1.82, 'b': 1.49,
        'v': 1.11, 'k': 0.69, 'x': 0.17, 'q': 0.11, 'j': 0.10, 'z': 0.07
    }
    
    def __init__(self):
        """Initialize frequency analyzer."""
        pass
    
    def calculate_frequencies(self, text: str) -> dict:
        """
        Calculate letter frequencies in text.
        
        Args:
            text: Input text
            
        Returns:
            Dictionary mapping letters to their frequencies (0-100)
        """
        text_lower = text.lower()
        letter_counts = {}
        total_letters = 0
        
        for char in text_lower:
            if char.isalpha():
                letter_counts[char] = letter_counts.get(char, 0) + 1
                total_letters += 1
        
        # Convert to percentages
        frequencies = {}
        for letter, count in letter_counts.items():
            frequencies[letter] = (count / total_letters * 100) if total_letters > 0 else 0
        
        return frequencies
    
    def chi_squared(self, observed: dict, expected: dict) -> float:
        """
        Calculate chi-squared statistic for frequency comparison.
        
        Args:
            observed: Observed frequencies
            expected: Expected frequencies
            
        Returns:
            Chi-squared value
        """
        chi_sq = 0.0
        for letter in string.ascii_lowercase:
            obs = observed.get(letter, 0)
            exp = expected.get(letter, 0)
            if exp > 0:
                chi_sq += ((obs - exp) ** 2) / exp
        return chi_sq
    
    def attack(self, ciphertext: str) -> List[Tuple[int, str, float]]:
        """
        Perform frequency analysis attack on Caesar cipher.
        
        Args:
            ciphertext: Encrypted text
            
        Returns:
            List of (shift, decrypted_text, chi_squared) tuples, sorted by best match
        """
        results = []
        
        for shift in range(26):
            cipher = CaesarCipher(shift)
            decrypted = cipher.decrypt(ciphertext)
            observed_freq = self.calculate_frequencies(decrypted)
            chi_sq = self.chi_squared(observed_freq, self.ENGLISH_FREQUENCIES)
            results.append((shift, decrypted, chi_sq))
        
        # Sort by chi-squared (lower is better match)
        results.sort(key=lambda x: x[2])
        return results
    
    def best_guess(self, ciphertext: str) -> Tuple[int, str]:
        """
        Get the most likely decryption based on frequency analysis.
        
        Args:
            ciphertext: Encrypted text
            
        Returns:
            Tuple of (best_shift, decrypted_text)
        """
        results = self.attack(ciphertext)
        if results:
            shift, text, _ = results[0]
            return (shift, text)
        return (0, ciphertext)

