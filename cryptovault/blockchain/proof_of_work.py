"""
Proof of Work Implementation
Adjustable difficulty for blockchain mining.
"""

from typing import Optional
from cryptovault.blockchain.block import Block


class ProofOfWork:
    """
    Proof of Work implementation with adjustable difficulty.
    """
    
    def __init__(self, difficulty: int = 4):
        """
        Initialize Proof of Work.
        
        Args:
            difficulty: Number of leading zeros required (default 4)
        """
        self.difficulty = difficulty
        self.target = 2 ** (256 - difficulty * 4)  # Simplified target calculation
    
    def calculate_target(self) -> int:
        """
        Calculate target hash value.
        
        Returns:
            Target value (hash must be less than this)
        """
        # Target = 2^(256 - difficulty*4)
        # This means difficulty leading hex zeros (4 bits each)
        return 2 ** (256 - self.difficulty * 4)
    
    def hash_meets_target(self, block_hash: str) -> bool:
        """
        Check if hash meets target (has required leading zeros).
        
        Args:
            block_hash: Block hash as hex string
            
        Returns:
            True if hash meets target
        """
        # Convert hex to integer
        hash_int = int(block_hash, 16)
        target = self.calculate_target()
        return hash_int < target
    
    def mine_block(self, block: Block, max_nonce: int = 2**32) -> Optional[int]:
        """
        Mine block by finding valid nonce.
        
        Args:
            block: Block to mine
            max_nonce: Maximum nonce to try
            
        Returns:
            Nonce if found, None otherwise
        """
        # Update Merkle root
        block.merkle_root = block.calculate_merkle_root()
        
        # Try nonces
        for nonce in range(max_nonce):
            block.nonce = nonce
            block_hash = block.hash()
            
            if self.hash_meets_target(block_hash):
                return nonce
        
        return None
    
    def verify_block(self, block: Block) -> bool:
        """
        Verify block's proof of work.
        
        Args:
            block: Block to verify
            
        Returns:
            True if proof of work is valid
        """
        # Verify Merkle root
        calculated_root = block.calculate_merkle_root()
        if calculated_root != block.merkle_root:
            return False
        
        # Verify hash meets target
        block_hash = block.hash()
        return self.hash_meets_target(block_hash)
    
    def set_difficulty(self, difficulty: int):
        """
        Set mining difficulty.
        
        Args:
            difficulty: Number of leading zeros required
        """
        if difficulty < 1 or difficulty > 64:
            raise ValueError("Difficulty must be between 1 and 64")
        self.difficulty = difficulty

