"""
Merkle Tree Implementation FROM SCRATCH
Educational implementation for exam project.

This is a from-scratch implementation - no crypto libraries used.
Uses simplified SHA-256 for hashing.
"""

from typing import List, Optional, Tuple
from cryptovault.core.sha256_simplified import SHA256Simplified


class MerkleTree:
    """
    Merkle tree implementation with proof generation and verification.
    
    Handles odd number of leaves by duplicating the last leaf.
    """
    
    def __init__(self, leaves: List[bytes]):
        """
        Initialize Merkle tree from list of leaf hashes.
        
        Args:
            leaves: List of data items (will be hashed) or already-hashed bytes
        """
        if not leaves:
            raise ValueError("Merkle tree requires at least one leaf")
        
        # Hash leaves if they're not already hashes
        # For this implementation, we assume leaves are already hashed
        # (or are data that should be hashed)
        self.leaves = []
        for leaf in leaves:
            if isinstance(leaf, str):
                leaf = leaf.encode('utf-8')
            if len(leaf) != 32:  # Not a hash, hash it
                leaf = SHA256Simplified.hash(leaf)
            self.leaves.append(leaf)
        
        self.tree = self._build_tree()
        self.root = self.tree[-1][0] if self.tree else None
    
    def _hash_pair(self, left: bytes, right: bytes) -> bytes:
        """
        Hash a pair of nodes.
        
        Args:
            left: Left node hash
            right: Right node hash
            
        Returns:
            Hash of concatenated pair
        """
        return SHA256Simplified.hash(left + right)
    
    def _build_tree(self) -> List[List[bytes]]:
        """
        Build Merkle tree from leaves.
        
        Returns:
            Tree structure as list of levels (each level is list of hashes)
        """
        tree = [self.leaves.copy()]  # Level 0: leaves
        current_level = self.leaves
        
        while len(current_level) > 1:
            next_level = []
            
            # Process pairs
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                # Handle odd number of nodes by duplicating last one
                if i + 1 < len(current_level):
                    right = current_level[i + 1]
                else:
                    right = current_level[i]  # Duplicate last node
                
                parent = self._hash_pair(left, right)
                next_level.append(parent)
            
            tree.append(next_level)
            current_level = next_level
        
        return tree
    
    def get_root(self) -> bytes:
        """
        Get Merkle root hash.
        
        Returns:
            Root hash as bytes
        """
        return self.root
    
    def get_root_hex(self) -> str:
        """
        Get Merkle root hash as hexadecimal string.
        
        Returns:
            Root hash as hex string
        """
        return self.root.hex() if self.root else ""
    
    def generate_proof(self, leaf_index: int) -> List[Tuple[bytes, str]]:
        """
        Generate Merkle proof for a leaf.
        
        Args:
            leaf_index: Index of leaf to prove
            
        Returns:
            List of (hash, position) tuples where position is 'left' or 'right'
        """
        if leaf_index < 0 or leaf_index >= len(self.leaves):
            raise ValueError(f"Leaf index {leaf_index} out of range")
        
        proof = []
        current_index = leaf_index
        
        for level in range(len(self.tree) - 1):
            current_level = self.tree[level]
            
            # Determine sibling
            if current_index % 2 == 0:
                # Even index: sibling is on the right
                if current_index + 1 < len(current_level):
                    sibling = current_level[current_index + 1]
                    position = 'right'
                else:
                    # Odd number of nodes: duplicate self
                    sibling = current_level[current_index]
                    position = 'right'
            else:
                # Odd index: sibling is on the left
                sibling = current_level[current_index - 1]
                position = 'left'
            
            proof.append((sibling, position))
            current_index = current_index // 2
        
        return proof
    
    @staticmethod
    def verify_proof(leaf_hash: bytes, proof: List[Tuple[bytes, str]], root_hash: bytes) -> bool:
        """
        Verify Merkle proof.
        
        Args:
            leaf_hash: Hash of the leaf being proven
            proof: List of (hash, position) tuples from generate_proof
            root_hash: Expected root hash
            
        Returns:
            True if proof is valid, False otherwise
        """
        current_hash = leaf_hash
        
        for sibling_hash, position in proof:
            if position == 'left':
                # Sibling is on left, current is on right
                current_hash = SHA256Simplified.hash(sibling_hash + current_hash)
            else:  # position == 'right'
                # Sibling is on right, current is on left
                current_hash = SHA256Simplified.hash(current_hash + sibling_hash)
        
        return current_hash == root_hash
    
    def get_tree_structure(self) -> dict:
        """
        Get tree structure for visualization/debugging.
        
        Returns:
            Dictionary with tree information
        """
        return {
            'num_leaves': len(self.leaves),
            'num_levels': len(self.tree),
            'root': self.root.hex() if self.root else None,
            'levels': [
                {
                    'level': i,
                    'num_nodes': len(level),
                    'hashes': [h.hex() for h in level]
                }
                for i, level in enumerate(self.tree)
            ]
        }
    
    def contains_leaf(self, leaf_hash: bytes) -> bool:
        """
        Check if a leaf hash exists in the tree.
        
        Args:
            leaf_hash: Hash to search for
            
        Returns:
            True if leaf exists, False otherwise
        """
        return leaf_hash in self.leaves

