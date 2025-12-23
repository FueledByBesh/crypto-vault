"""
Vigenère Cipher Implementation FROM SCRATCH
Educational implementation with Kasiski examination attack.

This is a from-scratch implementation - no crypto libraries used.
"""

import string
from typing import List, Tuple, Dict
from collections import Counter
import math


class VigenereCipher:
    """
    Vigenère cipher implementation.
    
    Security Note: This is for educational purposes only.
    Vigenère cipher is NOT secure for real-world use.
    """
    
    def __init__(self, key: str):
        """
        Initialize Vigenère cipher with a key.
        
        Args:
            key: Encryption key (alphabetic characters only)
        """
        if not key or not all(c.isalpha() for c in key):
            raise ValueError("Key must contain only alphabetic characters")
        self.key = key.lower()
        self.alphabet = string.ascii_lowercase
        self.alphabet_upper = string.ascii_uppercase
    
    def _get_key_char(self, index: int) -> str:
        """Get key character at position, wrapping if needed."""
        return self.key[index % len(self.key)]
    
    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt plaintext using Vigenère cipher.
        
        Args:
            plaintext: Text to encrypt
            
        Returns:
            Encrypted ciphertext
        """
        result = []
        key_idx = 0
        
        for char in plaintext:
            if char.islower():
                p_idx = self.alphabet.index(char)
                k_char = self._get_key_char(key_idx)
                k_idx = self.alphabet.index(k_char)
                c_idx = (p_idx + k_idx) % 26
                result.append(self.alphabet[c_idx])
                key_idx += 1
            elif char.isupper():
                p_idx = self.alphabet_upper.index(char)
                k_char = self._get_key_char(key_idx)
                k_idx = self.alphabet.index(k_char)
                c_idx = (p_idx + k_idx) % 26
                result.append(self.alphabet_upper[c_idx])
                key_idx += 1
            else:
                result.append(char)  # Non-alphabetic unchanged
        
        return ''.join(result)
    
    def decrypt(self, ciphertext: str) -> str:
        """
        Decrypt ciphertext using Vigenère cipher.
        
        Args:
            ciphertext: Text to decrypt
            
        Returns:
            Decrypted plaintext
        """
        result = []
        key_idx = 0
        
        for char in ciphertext:
            if char.islower():
                c_idx = self.alphabet.index(char)
                k_char = self._get_key_char(key_idx)
                k_idx = self.alphabet.index(k_char)
                p_idx = (c_idx - k_idx) % 26
                result.append(self.alphabet[p_idx])
                key_idx += 1
            elif char.isupper():
                c_idx = self.alphabet_upper.index(char)
                k_char = self._get_key_char(key_idx)
                k_idx = self.alphabet.index(k_char)
                p_idx = (c_idx - k_idx) % 26
                result.append(self.alphabet_upper[p_idx])
                key_idx += 1
            else:
                result.append(char)
        
        return ''.join(result)


class KasiskiExamination:
    """
    Kasiski examination attack on Vigenère cipher.
    Finds repeated patterns to determine key length.
    """
    
    def __init__(self):
        """Initialize Kasiski examination analyzer."""
        pass
    
    def find_repeated_sequences(self, text: str, min_length: int = 3) -> Dict[str, List[int]]:
        """
        Find repeated sequences in ciphertext.
        
        Args:
            text: Ciphertext to analyze
            min_length: Minimum sequence length to search for
            
        Returns:
            Dictionary mapping sequences to list of positions
        """
        text_clean = ''.join(c.lower() for c in text if c.isalpha())
        sequences = {}
        
        for length in range(min_length, min(len(text_clean) // 2, 10)):
            for i in range(len(text_clean) - length + 1):
                seq = text_clean[i:i + length]
                if seq not in sequences:
                    sequences[seq] = []
                sequences[seq].append(i)
        
        # Keep only sequences that appear multiple times
        repeated = {seq: positions for seq, positions in sequences.items() 
                   if len(positions) > 1}
        return repeated
    
    def calculate_distances(self, positions: List[int]) -> List[int]:
        """
        Calculate distances between repeated sequence positions.
        
        Args:
            positions: List of positions where sequence appears
            
        Returns:
            List of distances between consecutive positions
        """
        distances = []
        for i in range(len(positions) - 1):
            distances.append(positions[i + 1] - positions[i])
        return distances
    
    def find_key_length_candidates(self, ciphertext: str, top_n: int = 5) -> List[int]:
        """
        Find likely key lengths using Kasiski examination.
        
        Args:
            ciphertext: Encrypted text
            top_n: Number of candidates to return
            
        Returns:
            List of likely key lengths
        """
        repeated = self.find_repeated_sequences(ciphertext)
        all_distances = []
        
        for seq, positions in repeated.items():
            distances = self.calculate_distances(positions)
            all_distances.extend(distances)
        
        if not all_distances:
            return [1, 2, 3, 4, 5]  # Default guesses
        
        # Find common factors
        factor_counts = Counter()
        for dist in all_distances:
            for factor in range(2, min(dist + 1, 30)):
                if dist % factor == 0:
                    factor_counts[factor] += 1
        
        # Get most common factors (likely key lengths)
        candidates = [factor for factor, _ in factor_counts.most_common(top_n)]
        return candidates if candidates else [1, 2, 3, 4, 5]
    
    def index_of_coincidence(self, text: str) -> float:
        """
        Calculate index of coincidence for text.
        Higher values suggest monoalphabetic, lower suggest polyalphabetic.
        
        Args:
            text: Text to analyze
            
        Returns:
            Index of coincidence value
        """
        text_clean = ''.join(c.lower() for c in text if c.isalpha())
        if len(text_clean) < 2:
            return 0.0
        
        letter_counts = Counter(text_clean)
        n = len(text_clean)
        ic = 0.0
        
        for count in letter_counts.values():
            ic += count * (count - 1)
        
        ic = ic / (n * (n - 1))
        return ic
    
    def friedman_test(self, ciphertext: str, max_key_length: int = 20) -> int:
        """
        Use Friedman test to estimate key length.
        
        Args:
            ciphertext: Encrypted text
            max_key_length: Maximum key length to test
            
        Returns:
            Estimated key length
        """
        text_clean = ''.join(c.lower() for c in ciphertext if c.isalpha())
        n = len(text_clean)
        
        if n < 2:
            return 1
        
        # English IoC ≈ 0.0667, random IoC ≈ 0.0385
        kappa_r = 0.0385
        kappa_p = 0.0667
        
        best_length = 1
        best_score = float('inf')
        
        for key_len in range(1, min(max_key_length + 1, n // 2)):
            # Split into columns
            columns = [''] * key_len
            for i, char in enumerate(text_clean):
                if char.isalpha():
                    columns[i % key_len] += char
            
            # Calculate average IoC of columns
            avg_ic = 0.0
            valid_columns = 0
            for col in columns:
                if len(col) > 1:
                    ic = self.index_of_coincidence(col)
                    avg_ic += ic
                    valid_columns += 1
            
            if valid_columns > 0:
                avg_ic /= valid_columns
                # Score: how close to expected IoC
                score = abs(avg_ic - kappa_p)
                if score < best_score:
                    best_score = score
                    best_length = key_len
        
        return best_length


class VigenereCracker:
    """
    Complete Vigenère cipher cracker using Kasiski examination and frequency analysis.
    """
    
    # English letter frequencies
    ENGLISH_FREQUENCIES = {
        'e': 12.02, 't': 9.10, 'a': 8.12, 'o': 7.68, 'i': 7.31,
        'n': 6.95, 's': 6.28, 'r': 6.02, 'h': 5.92, 'd': 4.32,
        'l': 3.98, 'u': 2.88, 'c': 2.71, 'm': 2.61, 'f': 2.30,
        'y': 2.11, 'w': 2.09, 'g': 2.03, 'p': 1.82, 'b': 1.49,
        'v': 1.11, 'k': 0.69, 'x': 0.17, 'q': 0.11, 'j': 0.10, 'z': 0.07
    }
    
    def __init__(self):
        """Initialize Vigenère cracker."""
        self.kasiski = KasiskiExamination()
    
    def calculate_frequencies(self, text: str) -> dict:
        """Calculate letter frequencies in text."""
        text_lower = ''.join(c.lower() for c in text if c.isalpha())
        letter_counts = Counter(text_lower)
        total = len(text_lower)
        
        frequencies = {}
        for letter in string.ascii_lowercase:
            frequencies[letter] = (letter_counts.get(letter, 0) / total * 100) if total > 0 else 0
        
        return frequencies
    
    def chi_squared(self, observed: dict, expected: dict) -> float:
        """Calculate chi-squared statistic."""
        chi_sq = 0.0
        for letter in string.ascii_lowercase:
            obs = observed.get(letter, 0)
            exp = expected.get(letter, 0)
            if exp > 0:
                chi_sq += ((obs - exp) ** 2) / exp
        return chi_sq
    
    def find_key_letter(self, column: str) -> str:
        """
        Find most likely key letter for a column using frequency analysis.
        
        Args:
            column: Column of ciphertext (encrypted with same key letter)
            
        Returns:
            Most likely key letter
        """
        best_letter = 'a'
        best_score = float('inf')
        
        for shift in range(26):
            # Try decrypting column with this shift
            decrypted = ''
            for char in column:
                if char.islower():
                    idx = (string.ascii_lowercase.index(char) - shift) % 26
                    decrypted += string.ascii_lowercase[idx]
                elif char.isupper():
                    idx = (string.ascii_uppercase.index(char) - shift) % 26
                    decrypted += string.ascii_uppercase[idx]
            
            # Calculate frequency match
            observed = self.calculate_frequencies(decrypted)
            score = self.chi_squared(observed, self.ENGLISH_FREQUENCIES)
            
            if score < best_score:
                best_score = score
                best_letter = string.ascii_lowercase[shift]
        
        return best_letter
    
    def crack(self, ciphertext: str) -> Tuple[str, str]:
        """
        Crack Vigenère cipher.
        
        Args:
            ciphertext: Encrypted text
            
        Returns:
            Tuple of (recovered_key, decrypted_text)
        """
        # Step 1: Find key length
        key_length = self.kasiski.friedman_test(ciphertext)
        kasiski_candidates = self.kasiski.find_key_length_candidates(ciphertext)
        
        # Use Friedman result, but also try Kasiski candidates
        candidates_to_try = [key_length] + [k for k in kasiski_candidates if k != key_length]
        candidates_to_try = list(dict.fromkeys(candidates_to_try))[:3]  # Top 3 unique
        
        best_key = None
        best_decrypted = None
        best_score = float('inf')
        
        for key_len in candidates_to_try:
            # Step 2: Split into columns
            text_clean = ''.join(c for c in ciphertext if c.isalpha())
            columns = [''] * key_len
            for i, char in enumerate(text_clean):
                columns[i % key_len] += char.lower()
            
            # Step 3: Find key letter for each column
            recovered_key = ''
            for col in columns:
                if col:
                    key_letter = self.find_key_letter(col)
                    recovered_key += key_letter
                else:
                    recovered_key += 'a'
            
            # Step 4: Decrypt and score
            cipher = VigenereCipher(recovered_key)
            decrypted = cipher.decrypt(ciphertext)
            observed = self.calculate_frequencies(decrypted)
            score = self.chi_squared(observed, self.ENGLISH_FREQUENCIES)
            
            if score < best_score:
                best_score = score
                best_key = recovered_key
                best_decrypted = decrypted
        
        return (best_key or 'a', best_decrypted or ciphertext)

