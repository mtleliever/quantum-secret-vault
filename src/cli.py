"""
Command-line interface for the quantum secret vault.
"""

import argparse
import os
import sys
import json
import base64
from typing import List
from .core import QuantumSecretVault, SecurityConfig, SecurityLayer
from .utils.validation import validate_secret, validate_password

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Quantum-Resistant Secret Vault with Layered Security",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Create vault
  %(prog)s create --secret "my secret text" --password "my_password" --layers standard_encryption
  # Recover vault
  %(prog)s recover --vault-dir encrypted_secret --password "my_password"
        """
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Create subcommand
    create_parser = subparsers.add_parser("create", help="Create a new quantum vault")
    create_parser.add_argument("--secret", type=str, required=True, dest="secret", help="Secret text to encrypt")
    create_parser.add_argument("--password", type=str, required=True, dest="password", help="Encryption password")
    create_parser.add_argument("--layers", nargs='+', choices=[layer.value for layer in SecurityLayer], default=[SecurityLayer.STANDARD_ENCRYPTION.value], help="Security layers to apply (can combine multiple)")
    create_parser.add_argument("--shamir", nargs=2, type=int, metavar=('THRESHOLD', 'TOTAL'), help="Shamir sharing parameters (e.g., 5 7)")
    create_parser.add_argument("--parity", type=int, default=20, help="Reed-Solomon parity symbols per share (default: 20, corrects up to 10 byte errors)")

    create_parser.add_argument("--output-dir", type=str, default="quantum_vault", help="Output directory (default: quantum_vault)")
    create_parser.add_argument("--memory", type=int, default=524288, help="Argon2 memory cost in KiB (default: 512 MiB)")
    create_parser.add_argument("--time", type=int, default=5, help="Argon2 time cost iterations (default: 5)")
    create_parser.add_argument("--threads", type=int, default=1, help="Argon2 parallelism threads (default: 1)")
    create_parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    # Recover subcommand
    recover_parser = subparsers.add_parser("recover", help="Recover a secret from a vault directory (supports both single files and Shamir shares)")
    recover_parser.add_argument("--vault-dir", required=True, help="Path to vault directory (containing vault.bin or share files)")
    recover_parser.add_argument("--password", required=True, dest="password", help="Password for decryption")
    recover_parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed vault information before recovery")

    return parser.parse_args()

def validate_arguments(args: argparse.Namespace) -> None:
    """Validate command line arguments."""
    # Validate secret format
    if not validate_secret(args.secret):
        raise ValueError("Invalid secret format. Must be non-empty text.")
    
    # Validate password format
    if not validate_password(args.password):
        raise ValueError("Invalid password format. Must be 1-100 characters.")
    
    # Validate Argon2 parameters
    if args.memory < 65536:  # 64 MiB minimum for security
        raise ValueError("Argon2 memory cost must be at least 65,536 KiB (64 MiB) for security")
    if args.memory > 4194304:  # 4 GiB maximum (reasonable for high-security personal use)
        raise ValueError("Argon2 memory cost cannot exceed 4,194,304 KiB (4 GiB) - would be too slow")
    if args.time < 1:
        raise ValueError("Argon2 time cost must be at least 1")
    if args.time > 20:
        raise ValueError("Argon2 time cost cannot exceed 20 - would be too slow")
    if args.threads < 1 or args.threads > 8:
        raise ValueError("Argon2 parallelism must be between 1 and 8 threads")
    
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
        password=args.password,
        salt=os.urandom(32),
        argon2_memory_cost=args.memory,
        argon2_time_cost=args.time,
        argon2_parallelism=args.threads
    )
    
    if args.verbose:
        print(f"[*] Security layers: {', '.join([layer.value for layer in layers])}")
        print(f"[*] Secret length: {len(args.secret)} characters")
        print(f"[*] Password: {'*' * len(args.password)} (hidden for security)")
        print(f"[*] Argon2id parameters:")
        print(f"    - Memory: {args.memory:,} KiB ({args.memory/1024:.0f} MiB)")
        print(f"    - Time: {args.time} iterations")
        print(f"    - Threads: {args.threads}")
        print(f"[*] Computational resistance: Memory-hard key derivation with configurable difficulty")
        if SecurityLayer.SHAMIR_SHARING in layers:
            print(f"[*] Shamir sharing: {threshold}-of-{total} with {args.parity} parity shares")

    
    # Create vault
    vault = QuantumSecretVault(config)
    result = vault.create_vault(args.secret, args.output_dir)
    
    # Output results
    print(f"[+] Quantum vault created in {args.output_dir}")
    print(f"[+] Security layers: {', '.join(result['layers'])}")
    print(f"[+] Files created: {len(result['files_created'])}")
    
    if args.verbose:
        print(f"[*] Files:")
        for file_path in result['files_created']:
            print(f"    - {file_path}")
    
    if SecurityLayer.SHAMIR_SHARING in layers:
        print(f"[!] Distribute shares geographically for maximum security")

def recover_vault(args: argparse.Namespace) -> None:
    # AES-only recovery using QuantumSecretVault static method
    try:
        secret = QuantumSecretVault.recover_vault(args.vault_dir, args.password, show_details=args.verbose)
        print("[+] Decryption successful! Recovered secret:")
        print(secret)
    except Exception as e:
        print(f"[!] Decryption failed: {e}", file=sys.stderr)
        sys.exit(1)

def main():
    """Main entry point."""
    try:
        args = parse_arguments()
        if getattr(args, "command", None) == "create":
            create_vault(args)
        elif getattr(args, "command", None) == "recover":
            recover_vault(args)
        else:
            print("[!] Unknown command.", file=sys.stderr)
            sys.exit(1)
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
