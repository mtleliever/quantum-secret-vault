"""Tests for BIP-39 address derivation used on vault recover."""

import pytest

from src.utils.address_derivation import (
    ADDRESS_COUNT,
    derive_addresses,
    format_address_log,
    is_bip39_mnemonic,
)

# Well-known BIP-39 test vector (not a real wallet)
TEST_MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)


def test_is_bip39_mnemonic_accepts_valid_phrase():
    assert is_bip39_mnemonic(TEST_MNEMONIC)
    assert is_bip39_mnemonic(f"  {TEST_MNEMONIC}  ")


def test_is_bip39_mnemonic_rejects_invalid():
    assert not is_bip39_mnemonic("not a mnemonic")
    assert not is_bip39_mnemonic("abandon abandon abandon")
    assert not is_bip39_mnemonic("")


def test_derive_addresses_order_and_count():
    addresses = derive_addresses(TEST_MNEMONIC)

    assert list(addresses.keys()) == ["bitcoin", "ethereum", "solana"]
    assert len(addresses["bitcoin"]) == ADDRESS_COUNT
    assert len(addresses["ethereum"]) == ADDRESS_COUNT
    assert len(addresses["solana"]) == ADDRESS_COUNT

    # Known BIP-44 vectors for this mnemonic (Ian Coleman / BIP39 test vector)
    assert addresses["bitcoin"][0].startswith("1")
    assert addresses["bitcoin"][0] == "1LqBGSKuX5yYUonjxT5qGfpQpvnZrJ0zVf"
    assert addresses["ethereum"][0].lower() == "0x9858effd232b4033e47d90003d41ec34ecaeda94"
    assert len(addresses["solana"][0]) >= 32
    assert all(addresses["bitcoin"][i] != addresses["bitcoin"][j] for i in range(5) for j in range(i + 1, 5))
    assert all(addresses["solana"][i] != addresses["solana"][j] for i in range(5) for j in range(i + 1, 5))


def test_format_address_log_order():
    addresses = derive_addresses(TEST_MNEMONIC)
    log = format_address_log(addresses)

    btc_pos = log.index("Bitcoin:")
    eth_pos = log.index("Ethereum:")
    sol_pos = log.index("Solana:")
    assert btc_pos < eth_pos < sol_pos
    assert addresses["bitcoin"][0] in log
    assert addresses["ethereum"][0] in log
    assert addresses["solana"][0] in log


def test_derive_addresses_rejects_non_mnemonic():
    with pytest.raises(ValueError, match="BIP-39"):
        derive_addresses("just some secret text")
