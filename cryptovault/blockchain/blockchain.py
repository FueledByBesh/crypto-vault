"""
Blockchain Audit Ledger
Complete blockchain implementation with validation and integrity checks.
"""

import time
from typing import List, Optional, Tuple
from cryptovault.blockchain.block import Block, Transaction
from cryptovault.blockchain.proof_of_work import ProofOfWork
from cryptovault.core.merkle_tree import MerkleTree
from cryptovault.core.sha256_simplified import SHA256Simplified


class Blockchain:
    """
    Blockchain audit ledger for security events.
    Provides immutable audit trail.
    """
    
    def __init__(self, difficulty: int = 4):
        """
        Initialize blockchain.
        
        Args:
            difficulty: Proof of Work difficulty
        """
        self.chain: List[Block] = []
        self.pending_transactions: List[Transaction] = []
        self.proof_of_work = ProofOfWork(difficulty)
        
        # Create genesis block
        self._create_genesis_block()
    
    def _create_genesis_block(self):
        """Create the first block (genesis block)."""
        genesis = Block(
            index=0,
            timestamp=time.time(),
            previous_hash="0" * 64,  # 64 hex chars = 256 bits
            nonce=0,
            merkle_root="",
            transactions=[]
        )
        genesis.merkle_root = genesis.calculate_merkle_root()
        self.chain.append(genesis)
    
    def get_latest_block(self) -> Block:
        """Get the most recent block."""
        return self.chain[-1]
    
    def add_transaction(self, transaction: Transaction):
        """
        Add transaction to pending pool.
        
        Args:
            transaction: Transaction to add
        """
        self.pending_transactions.append(transaction)
    
    def mine_pending_transactions(self) -> Optional[Block]:
        """
        Mine pending transactions into a new block.
        
        Returns:
            Newly mined block, or None if mining failed
        """
        if not self.pending_transactions:
            return None
        
        # Create new block
        latest_block = self.get_latest_block()
        new_block = Block(
            index=len(self.chain),
            timestamp=time.time(),
            previous_hash=latest_block.hash(),
            nonce=0,
            merkle_root="",
            transactions=self.pending_transactions.copy()
        )
        
        # Mine block (find valid nonce)
        nonce = self.proof_of_work.mine_block(new_block)
        if nonce is None:
            return None
        
        # Add to chain
        self.chain.append(new_block)
        
        # Clear pending transactions
        self.pending_transactions = []
        
        return new_block
    
    def validate_chain(self) -> Tuple[bool, Optional[str]]:
        """
        Validate entire blockchain integrity.
        
        Returns:
            Tuple of (is_valid, error_message)
        """
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]
            
            # Verify previous hash link
            if current_block.previous_hash != previous_block.hash():
                return (False, f"Block {i}: Previous hash mismatch")
            
            # Verify proof of work
            if not self.proof_of_work.verify_block(current_block):
                return (False, f"Block {i}: Invalid proof of work")
            
            # Verify Merkle root
            calculated_root = current_block.calculate_merkle_root()
            if calculated_root != current_block.merkle_root:
                return (False, f"Block {i}: Merkle root mismatch")
        
        return (True, None)
    
    def get_block(self, index: int) -> Optional[Block]:
        """
        Get block by index.
        
        Args:
            index: Block index
            
        Returns:
            Block if found, None otherwise
        """
        if 0 <= index < len(self.chain):
            return self.chain[index]
        return None
    
    def get_transaction_proof(self, transaction: Transaction) -> Optional[dict]:
        """
        Generate Merkle proof for a transaction.
        
        Args:
            transaction: Transaction to prove
            
        Returns:
            Dictionary with proof data, or None if transaction not found
        """
        tx_hash = transaction.hash()
        
        # Find block containing transaction
        for block in self.chain:
            for i, tx in enumerate(block.transactions):
                if tx.hash() == tx_hash:
                    # Generate Merkle proof
                    tx_hashes = [tx.hash() for tx in block.transactions]
                    merkle_tree = MerkleTree(tx_hashes)
                    proof = merkle_tree.generate_proof(i)
                    
                    return {
                        'block_index': block.index,
                        'transaction_index': i,
                        'merkle_root': block.merkle_root,
                        'proof': [(h.hex(), pos) for h, pos in proof],
                        'transaction_hash': tx_hash.hex()
                    }
        
        return None
    
    def verify_transaction_proof(self, transaction: Transaction, proof_data: dict) -> bool:
        """
        Verify Merkle proof for a transaction.
        
        Args:
            transaction: Transaction to verify
            proof_data: Proof data from get_transaction_proof
            
        Returns:
            True if proof is valid
        """
        tx_hash = transaction.hash()
        block = self.get_block(proof_data['block_index'])
        
        if not block:
            return False
        
        if block.merkle_root != proof_data['merkle_root']:
            return False
        
        # Reconstruct proof format
        proof = [
            (bytes.fromhex(h), pos)
            for h, pos in proof_data['proof']
        ]
        
        # Verify using MerkleTree
        return MerkleTree.verify_proof(
            tx_hash,
            proof,
            bytes.fromhex(proof_data['merkle_root'])
        )
    
    def get_chain_info(self) -> dict:
        """
        Get blockchain information.
        
        Returns:
            Dictionary with chain statistics
        """
        total_transactions = sum(len(block.transactions) for block in self.chain)
        
        return {
            'length': len(self.chain),
            'difficulty': self.proof_of_work.difficulty,
            'total_transactions': total_transactions,
            'pending_transactions': len(self.pending_transactions),
            'is_valid': self.validate_chain()[0]
        }
    
    def create_transaction(self, action: str, user: str, data: str,
                          metadata: Optional[dict] = None) -> Transaction:
        """
        Create a new transaction.
        
        Args:
            action: Action type (e.g., "login", "encrypt_file")
            user: Username
            data: Transaction data (will be hashed)
            metadata: Optional metadata
            
        Returns:
            New transaction
        """
        # Hash sensitive data
        data_hash = SHA256Simplified.hash(data.encode('utf-8')).hex()
        
        transaction = Transaction(
            action=action,
            user=user,
            timestamp=time.time(),
            data_hash=data_hash,
            metadata=metadata or {}
        )
        
        return transaction

