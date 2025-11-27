"""
Shamir Secret Sharing with integrated Reed-Solomon error correction.

This implementation uses a proper layered approach:
1. Shamir Secret Sharing: Creates k-of-n threshold shares (any k shares can reconstruct)
2. Reed-Solomon Error Correction: Embeds error correction within each share

Architecture:
- Creates exactly 'total' shares (not total + parity)
- Each share contains Reed-Solomon encoded data for corruption protection
- Any 'threshold' shares can recover the secret, even with minor corruption
- Parity data is embedded within each share, not as separate files

Example:
    shamir = ShamirSharing(threshold=3, total=5, parity=2)
    shares = shamir.split_secret("my secret")  # Creates 5 shares
    recovered = shamir.recover_secret(shares[:3])  # Any 3 shares work
"""

from typing import List
from pyseltongue import SecretSharer
from reedsolo import RSCodec

class ShamirSharing:
    """
    Shamir Secret Sharing with integrated Reed-Solomon error correction.
    
    Implements proper cryptographic best practices by applying Reed-Solomon
    error correction to each individual Shamir share, rather than creating
    separate parity shares. This provides corruption protection while 
    maintaining the k-of-n threshold property.
    """
    
    def __init__(self, threshold: int, total: int, parity: int = 2):
        """
        Initialize Shamir sharing.
        
        Args:
            threshold: Minimum number of shares needed to recover (must be >= 2)
            total: Total number of shares to create (must be >= threshold)
            parity: Number of Reed-Solomon parity symbols per share
            
        Raises:
            ValueError: If parameters are invalid
            
        Security Note:
            Threshold must be at least 2. With threshold=1, all shares would
            contain the complete secret, defeating the purpose of secret sharing.
        """
        # Validate parameters with security-focused checks
        if threshold < 2:
            raise ValueError(
                f"Threshold ({threshold}) must be at least 2. "
                "With threshold=1, shares would contain the complete secret, "
                "defeating the purpose of secret sharing."
            )
        if total < 2:
            raise ValueError(f"Total ({total}) must be at least 2")
        if threshold > total:
            raise ValueError(f"Threshold ({threshold}) cannot be greater than total ({total})")
        if parity < 0:
            raise ValueError(f"Parity ({parity}) cannot be negative")
        if parity > 255:
            raise ValueError(f"Parity ({parity}) cannot exceed 255 (Reed-Solomon limit)")
        
        self.threshold = threshold
        self.total = total
        self.parity = parity
    
    def split_secret(self, secret: str) -> List[bytes]:
        """
        Split secret into Shamir shares with embedded Reed-Solomon error correction.
        
        Args:
            secret: Secret string to split
            
        Returns:
            List of Reed-Solomon encoded share bytes (exactly 'total' shares)
        """
        if not secret:
            raise ValueError("Secret cannot be empty")
        
        # Convert secret to numeric string that pyseltongue can handle
        secret_bytes = secret.encode('utf-8')
        numeric_secret = ''.join(f'{byte:03d}' for byte in secret_bytes)
        
        # Split into Shamir shares using pyseltongue
        try:
            # Create exactly 'total' Shamir shares (not total + parity)
            shamir_shares = SecretSharer.split_secret(numeric_secret, self.threshold, self.total)
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
                shamir_shares = []
                for i in range(self.total):
                    combined_share = '|'.join(all_chunk_shares[j][i] for j in range(len(all_chunk_shares)))
                    shamir_shares.append(combined_share)
            else:
                # Some other error, re-raise
                raise
        
        # Convert Shamir shares to bytes
        share_bytes = [s.encode('utf-8') for s in shamir_shares]
        
        # Apply Reed-Solomon error correction to each share individually
        if self.parity > 0:
            rsc = RSCodec(self.parity)
            rs_encoded_shares = []
            
            for share_data in share_bytes:
                # Convert bytes to list of integers for Reed-Solomon
                share_ints = list(share_data)
                
                # Apply Reed-Solomon encoding (embeds error correction within the share)
                encoded_ints = rsc.encode(share_ints)
                
                # Convert back to bytes
                rs_encoded_shares.append(bytes(encoded_ints))
            
            return rs_encoded_shares
        else:
            # No Reed-Solomon, just return raw Shamir shares
            return share_bytes
    
    def recover_secret(self, shares: List[bytes]) -> str:
        """
        Recover secret from Reed-Solomon encoded shares with automatic error correction.
        
        Args:
            shares: List of Reed-Solomon encoded share bytes
            
        Returns:
            Recovered secret string
        """
        if len(shares) < self.threshold:
            raise ValueError(f"Not enough shares: need at least {self.threshold}, got {len(shares)}")
        
        # Step 1: Apply Reed-Solomon decoding to each share (error correction)
        if self.parity > 0:
            rsc = RSCodec(self.parity)
            decoded_shares = []
            
            for i, share in enumerate(shares[:self.threshold]):  # Only use threshold number of shares
                try:
                    # Convert bytes to list of integers for Reed-Solomon
                    share_ints = list(share)
                    
                    # Apply Reed-Solomon decoding to correct any errors
                    decoded_result = rsc.decode(share_ints)
                    
                    # rsc.decode returns (corrected_message, corrected_ecc) tuple
                    # We only need the corrected message part
                    if isinstance(decoded_result, tuple):
                        decoded_ints = decoded_result[0]  # Get the message part
                    else:
                        decoded_ints = decoded_result
                    
                    # Convert to bytes - decoded_ints should be a list/array of ints
                    clean_share_data = bytes(list(decoded_ints))
                    decoded_shares.append(clean_share_data)
                    
                except Exception as e:
                    # If Reed-Solomon correction fails, the share might be too corrupted
                    raise ValueError(f"Failed to correct errors in share {i}: {e}")
            
            # Convert corrected shares to strings for Shamir reconstruction
            share_strings = [share.decode('utf-8') for share in decoded_shares]
        else:
            # No Reed-Solomon, use shares directly
            share_strings = [share.decode('utf-8') for share in shares[:self.threshold]]
        
        # Step 2: Apply Shamir secret reconstruction
        
        # Check if this is a chunked secret (contains '|' separator)
        if '|' in share_strings[0]:
            # This is a chunked secret, need to recover each chunk
            # Split each share into chunks
            chunk_shares = []
            for share in share_strings:
                chunks = share.split('|')
                chunk_shares.append(chunks)
            
            # Recover each chunk using Shamir
            recovered_chunks = []
            num_chunks = len(chunk_shares[0])
            for chunk_idx in range(num_chunks):
                chunk_shares_for_recovery = [chunk_shares[i][chunk_idx] for i in range(self.threshold)]
                recovered_chunk = SecretSharer.recover_secret(chunk_shares_for_recovery)
                recovered_chunks.append(recovered_chunk)
            
            # Combine chunks
            numeric_secret = ''.join(recovered_chunks)
        else:
            # Standard Shamir reconstruction
            numeric_secret = SecretSharer.recover_secret(share_strings)
        
        # Step 3: Convert numeric string back to original secret
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
            "total_shares": self.total,  # Reed-Solomon parity is embedded, not separate
            "error_correction": "Reed-Solomon" if self.parity > 0 else "None"
        } 