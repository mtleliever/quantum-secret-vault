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
    pbkdf2_iterations: int = 2000000  # Very high security default for personal crypto seeds
    
    def has_layer(self, layer: SecurityLayer) -> bool:
        """Check if a specific security layer is enabled"""
        return layer in self.layers 