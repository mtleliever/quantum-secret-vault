"""
Command-line interface for the quantum secret vault.
"""

import argparse
import os
import sys
from typing import List

from .core import QuantumSecretVault, SecurityConfig, SecurityLayer

def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Quantum-Resistant Secret Vault with Layered Security",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic quantum security only
  %(prog)s --seed "word1 word2 ... word24" --passphrase "my_25th_word" --layers quantum_encryption

  # Quantum + standard encryption
  %(prog)s --seed "word1 word2 ... word24" --passphrase "my_25th_word" --layers standard_encryption quantum_encryption

  # Quantum + shamir sharing (5-of-7)
  %(prog)s --seed "word1 word2 ... word24" --passphrase "my_25th_word" --layers quantum_encryption shamir_sharing --shamir 5 7

  # Full security stack
  %(prog)s --seed "word1 word2 ... word24" --passphrase "my_25th_word" --layers standard_encryption quantum_encryption shamir_sharing steganography --shamir 5 7 --images image1.png image2.png image3.png image4.png image5.png image6.png image7.png
        """
    )
    
    # Required arguments
    parser.add_argument(
        "--seed", 
        type=str, 
        required=True, 
        help="BIP-39 seed phrase (24 words)"
    )
    parser.add_argument(
        "--passphrase", 
        type=str, 
        required=True, 
        help="BIP-39 passphrase (25th word)"
    )
    
    # Security layers
    parser.add_argument(
        "--layers", 
        nargs='+', 
        choices=[layer.value for layer in SecurityLayer], 
        default=[SecurityLayer.QUANTUM_ENCRYPTION.value], 
        help="Security layers to apply (can combine multiple)"
    )
    
    # Shamir sharing parameters
    parser.add_argument(
        "--shamir", 
        nargs=2, 
        type=int, 
        metavar=('THRESHOLD', 'TOTAL'),
        help="Shamir sharing parameters (e.g., 5 7)"
    )
    parser.add_argument(
        "--parity", 
        type=int, 
        default=2, 
        help="Reed-Solomon parity shares (default: 2)"
    )
    
    # Steganography
    parser.add_argument(
        "--images", 
        nargs='+', 
        help="Image files for steganography"
    )
    
    # Output
    parser.add_argument(
        "--output-dir", 
        type=str, 
        default="quantum_vault", 
        help="Output directory (default: quantum_vault)"
    )
    
    # Verbosity
    parser.add_argument(
        "-v", "--verbose", 
        action="store_true", 
        help="Verbose output"
    )
    
    return parser.parse_args()

def validate_arguments(args: argparse.Namespace) -> None:
    """Validate command line arguments."""
    # Parse security layers
    layers = [SecurityLayer(layer) for layer in args.layers]
    
    # Validate Shamir parameters if Shamir sharing is selected
    if SecurityLayer.SHAMIR_SHARING in layers:
        if not args.shamir:
            raise ValueError("--shamir THRESHOLD TOTAL is required when using shamir_sharing layer")
        threshold, total = args.shamir
        if threshold > total:
            raise ValueError("Shamir threshold cannot be greater than total")
        if threshold < 2:
            raise ValueError("Shamir threshold must be at least 2")
        if total < 2:
            raise ValueError("Shamir total must be at least 2")
    
    # Validate steganography requirements
    if SecurityLayer.STEGANOGRAPHY in layers:
        if not args.images:
            raise ValueError("--images is required when using steganography layer")
        
        # Check if we have enough images for all shares
        if SecurityLayer.SHAMIR_SHARING in layers:
            required_images = args.shamir[1] + args.parity if args.shamir else 1
            if len(args.images) < required_images:
                raise ValueError(f"Need at least {required_images} images for steganography, got {len(args.images)}")
        else:
            if len(args.images) < 1:
                raise ValueError("Need at least 1 image for steganography")

def create_vault(args: argparse.Namespace) -> None:
    """Create the quantum vault with specified configuration."""
    # Parse and validate arguments
    layers = [SecurityLayer(layer) for layer in args.layers]
    validate_arguments(args)
    
    # Get Shamir parameters
    threshold, total = args.shamir if args.shamir else (5, 7)
    
    # Create security configuration
    config = SecurityConfig(
        layers=layers,
        shamir_threshold=threshold,
        shamir_total=total,
        parity_shares=args.parity,
        passphrase=args.passphrase,
        salt=os.urandom(32)
    )
    
    if args.verbose:
        print(f"[*] Security layers: {', '.join([layer.value for layer in layers])}")
        if SecurityLayer.SHAMIR_SHARING in layers:
            print(f"[*] Shamir sharing: {threshold}-of-{total} with {args.parity} parity shares")
        if SecurityLayer.STEGANOGRAPHY in layers:
            print(f"[*] Steganography: {len(args.images)} images provided")
    
    # Create vault
    vault = QuantumSecretVault(config)
    result = vault.create_vault(args.seed, args.output_dir, args.images)
    
    # Output results
    print(f"[+] Quantum vault created in {args.output_dir}")
    print(f"[+] Security layers: {', '.join(result['layers_used'])}")
    print(f"[+] Files created: {len(result['files_created'])}")
    
    if args.verbose:
        print(f"[*] Files:")
        for file_path in result['files_created']:
            print(f"    - {file_path}")
    
    if SecurityLayer.QUANTUM_ENCRYPTION in layers:
        print(f"[!] Securely archive quantum private keys if generated")
    
    if SecurityLayer.SHAMIR_SHARING in layers:
        print(f"[!] Distribute shares geographically for maximum security")

def main():
    """Main entry point."""
    try:
        args = parse_arguments()
        create_vault(args)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nOperation cancelled by user", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main() 