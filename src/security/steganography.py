"""
Steganography using steghide for robust data hiding.
"""

import subprocess
import secrets
import string
from typing import Optional

class Steganography:
    """Steganography using steghide for robust hiding"""
    
    def __init__(self, password: Optional[str] = None):
        """
        Initialize steganography.
        
        Args:
            password: Password for steganography operations (generated if not provided)
        """

        
        if password is None:
            # Generate a secure random password
            alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
            self.password = ''.join(secrets.choice(alphabet) for _ in range(32))
        else:
            self.password = password
    
    def embed_data(self, data_file: str, cover_image: str, output_image: str) -> bool:
        """
        Embed data into image using steghide.
        
        Args:
            data_file: Path to file containing data to hide
            cover_image: Path to cover image
            output_image: Path for output stego image
            
        Returns:
            True if successful, False otherwise
        """
        try:
            cmd = [
                "steghide",
                "embed",
                "-ef", data_file,
                "-cf", cover_image,
                "-p", self.password,
                "-sf", output_image
            ]
            subprocess.run(cmd, check=True, capture_output=True)
            return True
        except subprocess.CalledProcessError:
            return False
    
    def extract_data(self, stego_image: str, output_file: str) -> bool:
        """
        Extract data from stego image.
        
        Args:
            stego_image: Path to stego image
            output_file: Path for extracted data file
            
        Returns:
            True if successful, False otherwise
        """
        try:
            cmd = [
                "steghide",
                "extract",
                "-sf", stego_image,
                "-p", self.password,
                "-xf", output_file
            ]
            subprocess.run(cmd, check=True, capture_output=True)
            return True
        except subprocess.CalledProcessError:
            return False
    
    def get_info(self, stego_image: str) -> Optional[dict]:
        """
        Get information about embedded data in stego image.
        
        Args:
            stego_image: Path to stego image
            
        Returns:
            Dictionary with embedded data info or None if failed
        """
        try:
            cmd = [
                "steghide",
                "info",
                "-sf", stego_image
            ]
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            return {"info": result.stdout}
        except subprocess.CalledProcessError:
            return None 