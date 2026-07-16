"""
Derive cryptocurrency addresses from a BIP-39 mnemonic seed phrase.
"""

from __future__ import annotations

from typing import Dict, List

from bip_utils import (
    Bip39MnemonicValidator,
    Bip39SeedGenerator,
    Bip44,
    Bip44Changes,
    Bip44Coins,
)

ADDRESS_COUNT = 5


def is_bip39_mnemonic(text: str) -> bool:
    """Return True if text is a valid BIP-39 mnemonic."""
    try:
        return bool(Bip39MnemonicValidator().IsValid(text.strip()))
    except Exception:
        return False


def derive_addresses(mnemonic: str, count: int = ADDRESS_COUNT) -> Dict[str, List[str]]:
    """
    Derive the first `count` addresses for Bitcoin, Ethereum, and Solana.

    Paths:
      - Bitcoin:  m/44'/0'/0'/0/i
      - Ethereum: m/44'/60'/0'/0/i
      - Solana:   m/44'/501'/i'/0'  (Phantom-style)
    """
    mnemonic = mnemonic.strip()
    if not is_bip39_mnemonic(mnemonic):
        raise ValueError("Recovered secret is not a valid BIP-39 mnemonic")

    seed_bytes = Bip39SeedGenerator(mnemonic).Generate()

    btc_mst = Bip44.FromSeed(seed_bytes, Bip44Coins.BITCOIN)
    eth_mst = Bip44.FromSeed(seed_bytes, Bip44Coins.ETHEREUM)
    sol_mst = Bip44.FromSeed(seed_bytes, Bip44Coins.SOLANA)

    bitcoin: List[str] = []
    ethereum: List[str] = []
    solana: List[str] = []

    for i in range(count):
        bitcoin.append(
            btc_mst.Purpose()
            .Coin()
            .Account(0)
            .Change(Bip44Changes.CHAIN_EXT)
            .AddressIndex(i)
            .PublicKey()
            .ToAddress()
        )
        ethereum.append(
            eth_mst.Purpose()
            .Coin()
            .Account(0)
            .Change(Bip44Changes.CHAIN_EXT)
            .AddressIndex(i)
            .PublicKey()
            .ToAddress()
        )
        # Phantom / Solflare style: m/44'/501'/i'/0'
        solana.append(
            sol_mst.Purpose()
            .Coin()
            .Account(i)
            .Change(Bip44Changes.CHAIN_EXT)
            .PublicKey()
            .ToAddress()
        )

    return {
        "bitcoin": bitcoin,
        "ethereum": ethereum,
        "solana": solana,
    }


def format_address_log(addresses: Dict[str, List[str]]) -> str:
    """Format derived addresses for recover output (BTC, then ETH, then SOL)."""
    lines = [
        "",
        "[+] First 5 derived addresses:",
        "",
        "Bitcoin:",
    ]
    for i, addr in enumerate(addresses["bitcoin"]):
        lines.append(f"  {i}: {addr}")

    lines.append("")
    lines.append("Ethereum:")
    for i, addr in enumerate(addresses["ethereum"]):
        lines.append(f"  {i}: {addr}")

    lines.append("")
    lines.append("Solana:")
    for i, addr in enumerate(addresses["solana"]):
        lines.append(f"  {i}: {addr}")

    return "\n".join(lines)
