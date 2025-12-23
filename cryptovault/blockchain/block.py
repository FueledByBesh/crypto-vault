"""
Block Structure for Blockchain Audit Ledger
"""

import time
import hashlib
from typing import List, Optional
from dataclasses import dataclass, field
from cryptovault.core.merkle_tree import MerkleTree
from cryptovault.core.sha256_simplified import SHA256Simplified


@dataclass
class Transaction:
    """Transaction in the blockchain."""
    action: str  # e.g., "login", "encrypt_file", "send_message"
    user: str
    timestamp: float
    data_hash: str  # Hash of transaction data
    metadata: dict = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        """Convert transaction to dictionary."""
        return {
            'action': self.action,
            'user': self.user,
            'timestamp': self.timestamp,
            'data_hash': self.data_hash,
            'metadata': self.metadata
        }
    
    def hash(self) -> bytes:
        """Calculate transaction hash."""
        tx_str = f"{self.action}:{self.user}:{self.timestamp}:{self.data_hash}"
        return SHA256Simplified.hash(tx_str.encode('utf-8'))


@dataclass
class Block:
    """
    Block structure for blockchain.
    Contains: index, timestamp, previous_hash, nonce, Merkle root, transactions.
    """
    index: int
    timestamp: float
    previous_hash: str
    nonce: int
    merkle_root: str
    transactions: List[Transaction] = field(default_factory=list)
    
    def calculate_merkle_root(self) -> str:
        """
        Calculate Merkle root from transactions.
        
        Returns:
            Merkle root as hex string
        """
        if not self.transactions:
            # Empty block: use zero hash
            return SHA256Simplified.hash(b"empty").hex()
        
        # Get transaction hashes
        tx_hashes = [tx.hash() for tx in self.transactions]
        
        # Build Merkle tree
        merkle_tree = MerkleTree(tx_hashes)
        return merkle_tree.get_root_hex()
    
    def hash(self) -> str:
        """
        Calculate block hash.
        
        Returns:
            Block hash as hex string
        """
        block_header = (
            f"{self.index}:{self.timestamp}:{self.previous_hash}:"
            f"{self.nonce}:{self.merkle_root}"
        )
        return SHA256Simplified.hash(block_header.encode('utf-8')).hex()
    
    def to_dict(self) -> dict:
        """Convert block to dictionary."""
        return {
            'index': self.index,
            'timestamp': self.timestamp,
            'previous_hash': self.previous_hash,
            'nonce': self.nonce,
            'merkle_root': self.merkle_root,
            'transactions': [tx.to_dict() for tx in self.transactions],
            'hash': self.hash()
        }

