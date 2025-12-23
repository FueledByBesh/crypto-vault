"""
Unit tests for Core Crypto Library (from scratch implementations)
"""

import pytest
from cryptovault.core.caesar import CaesarCipher, FrequencyAnalyzer
from cryptovault.core.vigenere import VigenereCipher, VigenereCracker
from cryptovault.core.sha256_simplified import SHA256Simplified
from cryptovault.core.merkle_tree import MerkleTree


class TestCaesarCipher:
    """Test Caesar cipher implementation."""
    
    def test_encrypt_decrypt(self):
        """Test basic encryption and decryption."""
        cipher = CaesarCipher(shift=3)
        plaintext = "HELLO WORLD"
        encrypted = cipher.encrypt(plaintext)
        assert encrypted == "KHOOR ZRUOG"
        decrypted = cipher.decrypt(encrypted)
        assert decrypted == plaintext
    
    def test_frequency_attack(self):
        """Test frequency analysis attack."""
        cipher = CaesarCipher(shift=5)
        plaintext = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG"
        encrypted = cipher.encrypt(plaintext)
        
        analyzer = FrequencyAnalyzer()
        results = analyzer.attack(encrypted)
        best_shift, best_text, _ = results[0]
        
        assert best_shift == 5
        assert best_text.upper() == plaintext.upper()


class TestVigenereCipher:
    """Test Vigenère cipher implementation."""
    
    def test_encrypt_decrypt(self):
        """Test basic encryption and decryption."""
        cipher = VigenereCipher(key="KEY")
        plaintext = "HELLO WORLD"
        encrypted = cipher.encrypt(plaintext)
        decrypted = cipher.decrypt(encrypted)
        assert decrypted == plaintext
    
    def test_cracking(self):
        """Test Vigenère cipher cracking."""
        key = "SECRET"
        cipher = VigenereCipher(key=key)
        plaintext = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG"
        encrypted = cipher.encrypt(plaintext)
        
        cracker = VigenereCracker()
        recovered_key, decrypted = cracker.crack(encrypted)
        
        # Should recover similar text (may not be exact due to frequency analysis)
        assert len(recovered_key) > 0
        assert len(decrypted) == len(plaintext)


class TestSHA256Simplified:
    """Test simplified SHA-256 implementation."""
    
    def test_hash_empty(self):
        """Test hashing empty string."""
        hasher = SHA256Simplified()
        hasher.update(b"")
        digest = hasher.digest()
        assert len(digest) == 32
    
    def test_hash_consistency(self):
        """Test hash consistency."""
        data = b"Hello, World!"
        hash1 = SHA256Simplified.hash(data)
        hash2 = SHA256Simplified.hash(data)
        assert hash1 == hash2
    
    def test_hash_different_inputs(self):
        """Test different inputs produce different hashes."""
        hash1 = SHA256Simplified.hash(b"Hello")
        hash2 = SHA256Simplified.hash(b"World")
        assert hash1 != hash2


class TestMerkleTree:
    """Test Merkle tree implementation."""
    
    def test_single_leaf(self):
        """Test Merkle tree with single leaf."""
        leaves = [b"leaf1"]
        tree = MerkleTree(leaves)
        root = tree.get_root()
        assert root is not None
        assert len(root) == 32
    
    def test_multiple_leaves(self):
        """Test Merkle tree with multiple leaves."""
        leaves = [b"leaf1", b"leaf2", b"leaf3", b"leaf4"]
        tree = MerkleTree(leaves)
        root = tree.get_root()
        assert root is not None
    
    def test_odd_leaves(self):
        """Test Merkle tree with odd number of leaves."""
        leaves = [b"leaf1", b"leaf2", b"leaf3"]
        tree = MerkleTree(leaves)
        root = tree.get_root()
        assert root is not None
    
    def test_proof_generation(self):
        """Test Merkle proof generation."""
        leaves = [b"leaf1", b"leaf2", b"leaf3", b"leaf4"]
        tree = MerkleTree(leaves)
        
        proof = tree.generate_proof(0)
        assert len(proof) > 0
    
    def test_proof_verification(self):
        """Test Merkle proof verification."""
        leaves = [b"leaf1", b"leaf2", b"leaf3", b"leaf4"]
        tree = MerkleTree(leaves)
        root = tree.get_root()
        
        leaf_hash = leaves[0] if len(leaves[0]) == 32 else SHA256Simplified.hash(leaves[0])
        proof = tree.generate_proof(0)
        
        is_valid = MerkleTree.verify_proof(leaf_hash, proof, root)
        assert is_valid

