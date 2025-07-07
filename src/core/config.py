"""
Configuration classes for the quantum secret vault.
"""

from enum import Enum
from dataclasses import dataclass
from typing import List

class SecurityLayer(Enum):
    """Available security layers that can be combined"""
    STANDARD_ENCRYPTION = "standard_encryption"
    QUANTUM_ENCRYPTION = "quantum_encryption"
    SHAMIR_SHARING = "shamir_sharing"
    STEGANOGRAPHY = "steganography"

@dataclass
class SecurityConfig:
    """Configuration for security layers"""
    layers: List[SecurityLayer]
    shamir_threshold: int = 5
    shamir_total: int = 7
    parity_shares: int = 2
    passphrase: str = ""
    salt: bytes = b""
    # Argon2id parameters (more secure than PBKDF2)
    argon2_memory_cost: int = 524288   # 512 MiB memory usage (high security for crypto seeds)
    argon2_time_cost: int = 5          # 5 iterations (higher security)
    argon2_parallelism: int = 1        # Single thread
    
    def has_layer(self, layer: SecurityLayer) -> bool:
        """Check if a specific security layer is enabled"""
        return layer in self.layers 