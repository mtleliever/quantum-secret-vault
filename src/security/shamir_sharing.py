"""
Shamir Secret Sharing with Reed-Solomon error correction.
"""

from typing import List
from pyseltongue import SecretSharer
from reedsolo import RSCodec

class ShamirSharing:
    """Shamir Secret Sharing with Reed-Solomon error correction"""
    
    def __init__(self, threshold: int, total: int, parity: int = 2):
        """
        Initialize Shamir sharing.
        
        Args:
            threshold: Minimum number of shares needed to recover
            total: Total number of shares to create
            parity: Number of Reed-Solomon parity shares
        """
        self.threshold = threshold
        self.total = total
        self.parity = parity
    
    def split_secret(self, secret: str) -> List[bytes]:
        """
        Split secret into Shamir shares with Reed-Solomon parity.
        
        Args:
            secret: Secret string to split
            
        Returns:
            List of share bytes
        """
        # Split into Shamir shares
        shares = SecretSharer.split_secret(secret, self.threshold, self.total)
        
        # Add Reed-Solomon parity
        rsc = RSCodec(self.parity)
        encoded_shares = rsc.encode([s.encode('utf-8') for s in shares])
        
        # Convert array to list of bytes
        return [bytes(share) for share in encoded_shares]
    
    def recover_secret(self, shares: List[bytes]) -> str:
        """
        Recover secret from shares with error correction.
        
        Args:
            shares: List of share bytes
            
        Returns:
            Recovered secret string
        """
        # Decode Reed-Solomon
        rsc = RSCodec(self.parity)
        corrected_shares = rsc.decode(shares)
        
        # Convert back to strings for Shamir recovery
        share_strings = [bytes(share).decode('utf-8') for share in corrected_shares[:self.total]]
        
        # Recover with Shamir
        return SecretSharer.recover_secret(share_strings[:self.threshold])
    
    def get_share_info(self) -> dict:
        """
        Get information about the sharing configuration.
        
        Returns:
            Dictionary with sharing parameters
        """
        return {
            "threshold": self.threshold,
            "total": self.total,
            "parity": self.parity,
            "total_shares": self.total + self.parity
        } 