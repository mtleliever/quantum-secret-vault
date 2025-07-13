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
        # Validate parameters
        if threshold > total:
            raise ValueError(f"Threshold ({threshold}) cannot be greater than total ({total})")
        if threshold < 1:
            raise ValueError(f"Threshold ({threshold}) must be at least 1")
        if total < 1:
            raise ValueError(f"Total ({total}) must be at least 1")
        if parity < 0:
            raise ValueError(f"Parity ({parity}) cannot be negative")
        
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
        # Handle edge case: threshold=1 (pyseltongue requires >= 2)
        if self.threshold == 1:
            # For threshold=1, just return the secret as shares
            secret_bytes = secret.encode('utf-8')
            shares = [secret] * self.total
            share_bytes = [s.encode('utf-8') for s in shares]
            
            # Add parity shares if needed
            if self.parity > 0:
                for i in range(self.parity):
                    parity_share = share_bytes[i % len(share_bytes)]
                    share_bytes.append(parity_share)
            
            return share_bytes
        
        # Convert secret to numeric string that pyseltongue can handle
        # Use only digits 0-9 which are universally supported
        secret_bytes = secret.encode('utf-8')
        numeric_secret = ''.join(f'{byte:03d}' for byte in secret_bytes)
        
        # Try to split the secret, if it's too long, fall back to chunking
        try:
            # Split into Shamir shares using pyseltongue
            shares = SecretSharer.split_secret(numeric_secret, self.threshold, self.total)
        except ValueError as e:
            if "too long" in str(e):
                # Secret is too long, use chunking approach
                MAX_CHUNK_SIZE = 150  # Conservative chunk size
                chunk_size = MAX_CHUNK_SIZE // 3 * 3  # Ensure divisible by 3
                chunks = [numeric_secret[i:i+chunk_size] for i in range(0, len(numeric_secret), chunk_size)]
                
                # Process each chunk separately and combine
                all_chunk_shares = []
                for chunk in chunks:
                    chunk_shares = SecretSharer.split_secret(chunk, self.threshold, self.total)
                    all_chunk_shares.append(chunk_shares)
                
                # Combine chunk shares into final shares
                shares = []
                for i in range(self.total):
                    combined_share = '|'.join(all_chunk_shares[j][i] for j in range(len(all_chunk_shares)))
                    shares.append(combined_share)
            else:
                # Some other error, re-raise
                raise
        
        # Convert shares to bytes
        share_bytes = [s.encode('utf-8') for s in shares]
        
        # Apply Reed-Solomon error correction if parity > 0
        if self.parity > 0:
            rsc = RSCodec(self.parity)
            encoded_shares = []
            
            for share_data in share_bytes:
                # Convert bytes to list of integers for Reed-Solomon
                share_ints = list(share_data)
                
                # Apply Reed-Solomon encoding to get encoded data (original + parity)
                encoded_ints = rsc.encode(share_ints)
                
                # Convert back to bytes
                encoded_shares.append(bytes(encoded_ints))
            
            # Add parity shares (these are redundant encoded versions for additional protection)
            for i in range(self.parity):
                # Create additional parity shares by encoding original shares again
                parity_source = share_bytes[i % len(share_bytes)]
                parity_ints = list(parity_source)
                parity_encoded = rsc.encode(parity_ints)
                encoded_shares.append(bytes(parity_encoded))
            
            return encoded_shares
        else:
            # No Reed-Solomon, just return raw shares
            return share_bytes
    
    def recover_secret(self, shares: List[bytes]) -> str:
        """
        Recover secret from shares with error correction.
        
        Args:
            shares: List of share bytes
            
        Returns:
            Recovered secret string
        """
        # Apply Reed-Solomon error correction if parity > 0
        if self.parity > 0:
            rsc = RSCodec(self.parity)
            corrected_shares = []
            
            # Process the first 'total' shares (original shares, not parity shares)
            for i in range(min(self.total, len(shares))):
                try:
                    # Convert bytes to list of integers for Reed-Solomon
                    share_ints = list(shares[i])
                    
                    # Apply Reed-Solomon decoding to correct errors
                    decoded_result = rsc.decode(share_ints)
                    
                    # rsc.decode returns (corrected_message, corrected_ecc) tuple
                    # We only need the corrected message part
                    if isinstance(decoded_result, tuple):
                        decoded_ints = decoded_result[0]  # Get the message part
                    else:
                        decoded_ints = decoded_result
                    
                    # Convert to bytes - decoded_ints should be a list/array of ints
                    original_data = bytes(list(decoded_ints))
                    corrected_shares.append(original_data)
                    
                except Exception:
                    # If Reed-Solomon correction fails, try using the original share
                    # This might happen if the share is too corrupted or if it's not RS-encoded
                    corrected_shares.append(shares[i])
            
            # Convert corrected shares to strings
            share_strings = [share.decode('utf-8') for share in corrected_shares]
        else:
            # No Reed-Solomon, use shares directly
            share_strings = [share.decode('utf-8') for share in shares[:self.total]]
        
        # Handle edge case: threshold=1
        if self.threshold == 1:
            # For threshold=1, shares are just the original secret
            return share_strings[0]
        
        # Check if this is a chunked secret (contains '|' separator)
        if '|' in share_strings[0]:
            # This is a chunked secret, need to recover each chunk
            # Split each share into chunks
            chunk_shares = []
            for share in share_strings[:self.threshold]:
                chunks = share.split('|')
                chunk_shares.append(chunks)
            
            # Recover each chunk
            recovered_chunks = []
            num_chunks = len(chunk_shares[0])
            for chunk_idx in range(num_chunks):
                chunk_shares_for_recovery = [chunk_shares[i][chunk_idx] for i in range(self.threshold)]
                recovered_chunk = SecretSharer.recover_secret(chunk_shares_for_recovery)
                recovered_chunks.append(recovered_chunk)
            
            # Combine chunks
            numeric_secret = ''.join(recovered_chunks)
        else:
            # Recover with Shamir (use minimum threshold)
            numeric_secret = SecretSharer.recover_secret(share_strings[:self.threshold])
        
        # Convert numeric string back to original secret
        # Each byte was encoded as 3 digits (000-255)
        secret_bytes = []
        for i in range(0, len(numeric_secret), 3):
            byte_str = numeric_secret[i:i+3]
            if len(byte_str) == 3:
                secret_bytes.append(int(byte_str))
        
        return bytes(secret_bytes).decode('utf-8')
    
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