#!/usr/bin/env python3
"""
Quantum Secret Vault - Main Entry Point

This is the main entry point for the quantum secret vault application.
It delegates to the CLI module for command-line interface handling.
"""

from .cli import main

if __name__ == "__main__":
    main()
