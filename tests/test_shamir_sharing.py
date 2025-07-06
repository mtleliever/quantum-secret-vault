"""
Tests for Shamir secret sharing functionality.
"""

import pytest
from src.security.shamir_sharing import ShamirSharing

class TestShamirSharing:
    """Test suite for ShamirSharing class."""
    
    def test_initialization(self):
        """Test ShamirSharing initialization."""
        shamir = ShamirSharing(threshold=3, total=5, parity=2)
        assert shamir.threshold == 3
        assert shamir.total == 5
        assert shamir.parity == 2
    
    def test_split_and_recover_basic(self, sample_seed):
        """Test basic split and recover functionality."""
        shamir = ShamirSharing(threshold=3, total=5, parity=1)
        
        # Split the secret
        shares = shamir.split_secret(sample_seed)
        
        # Should have total + parity shares
        assert len(shares) == 6  # 5 + 1 parity
        
        # Recover with threshold shares
        recovered = shamir.recover_secret(shares[:3])
        assert recovered == sample_seed
    
    def test_split_and_recover_with_all_shares(self, sample_seed):
        """Test recovery with all shares."""
        shamir = ShamirSharing(threshold=3, total=5, parity=2)
        
        shares = shamir.split_secret(sample_seed)
        assert len(shares) == 7  # 5 + 2 parity
        
        # Recover with all shares
        recovered = shamir.recover_secret(shares)
        assert recovered == sample_seed
    
    def test_minimum_threshold_recovery(self, sample_seed):
        """Test recovery with exactly threshold number of shares."""
        shamir = ShamirSharing(threshold=3, total=5, parity=1)
        
        shares = shamir.split_secret(sample_seed)
        
        # Recover with exactly threshold shares
        recovered = shamir.recover_secret(shares[:3])
        assert recovered == sample_seed
    
    def test_insufficient_shares_failure(self, sample_seed):
        """Test that recovery fails with insufficient shares."""
        shamir = ShamirSharing(threshold=3, total=5, parity=1)
        
        shares = shamir.split_secret(sample_seed)
        
        # Try to recover with fewer than threshold shares
        with pytest.raises(Exception):
            shamir.recover_secret(shares[:2])
    
    def test_different_threshold_configurations(self, sample_seed):
        """Test various threshold configurations."""
        test_configs = [
            (2, 3, 1),  # 2-of-3 with 1 parity
            (3, 5, 2),  # 3-of-5 with 2 parity
            (5, 7, 2),  # 5-of-7 with 2 parity
            (2, 2, 1),  # 2-of-2 with 1 parity
        ]
        
        for threshold, total, parity in test_configs:
            shamir = ShamirSharing(threshold, total, parity)
            shares = shamir.split_secret(sample_seed)
            
            # Should have total + parity shares
            expected_shares = total + parity
            assert len(shares) == expected_shares
            
            # Should recover with threshold shares
            recovered = shamir.recover_secret(shares[:threshold])
            assert recovered == sample_seed
    
    def test_share_uniqueness(self, sample_seed):
        """Test that shares are unique."""
        shamir = ShamirSharing(threshold=3, total=5, parity=1)
        
        shares = shamir.split_secret(sample_seed)
        
        # All shares should be unique
        share_set = set(shares)
        assert len(share_set) == len(shares)
    
    def test_share_format(self, sample_seed):
        """Test that shares are in the correct format."""
        shamir = ShamirSharing(threshold=3, total=5, parity=1)
        
        shares = shamir.split_secret(sample_seed)
        
        for share in shares:
            # Shares should be bytes
            assert isinstance(share, bytes)
            # Shares should not be empty
            assert len(share) > 0
    
    def test_error_correction_capability(self, sample_seed):
        """Test Reed-Solomon error correction."""
        shamir = ShamirSharing(threshold=3, total=5, parity=2)
        
        shares = shamir.split_secret(sample_seed)
        
        # Simulate corruption of one share (replace with random data)
        import os
        corrupted_shares = shares.copy()
        corrupted_shares[1] = os.urandom(len(shares[1]))
        
        # Should still be able to recover with error correction
        recovered = shamir.recover_secret(corrupted_shares)
        assert recovered == sample_seed
    
    def test_get_share_info(self):
        """Test get_share_info method."""
        shamir = ShamirSharing(threshold=3, total=5, parity=2)
        
        info = shamir.get_share_info()
        
        assert info["threshold"] == 3
        assert info["total"] == 5
        assert info["parity"] == 2
        assert info["total_shares"] == 7  # 5 + 2
    
    def test_large_secret_handling(self):
        """Test handling of large secrets."""
        shamir = ShamirSharing(threshold=3, total=5, parity=1)
        
        # Create a large secret
        large_secret = "large_secret " * 1000  # ~13KB
        
        shares = shamir.split_secret(large_secret)
        recovered = shamir.recover_secret(shares[:3])
        
        assert recovered == large_secret
    
    def test_special_characters_in_secret(self):
        """Test handling of secrets with special characters."""
        shamir = ShamirSharing(threshold=3, total=5, parity=1)
        
        special_secret = "secret with special chars: !@#$%^&*()_+-=[]{}|;':\",./<>?"
        
        shares = shamir.split_secret(special_secret)
        recovered = shamir.recover_secret(shares[:3])
        
        assert recovered == special_secret
    
    def test_unicode_secret_handling(self):
        """Test handling of Unicode secrets."""
        shamir = ShamirSharing(threshold=3, total=5, parity=1)
        
        unicode_secret = "Unicode secret: 🚀🔒🌍🔑 测试 テスト"
        
        shares = shamir.split_secret(unicode_secret)
        recovered = shamir.recover_secret(shares[:3])
        
        assert recovered == unicode_secret 