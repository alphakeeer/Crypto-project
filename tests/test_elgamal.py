"""
pytest 单元测试：ElGamal
"""

import os
import random

import pytest
from crypto import (
    generate_elgamal_keypair,
    elgamal_encrypt,
    elgamal_decrypt,
)


@pytest.mark.parametrize("bits", [512, 1024])
def test_encrypt_decrypt_roundtrip(bits: int) -> None:
    pub, priv = generate_elgamal_keypair(bits)
    msg = random.randbytes(32) if hasattr(random, "randbytes") else os.urandom(32)
    cipher = elgamal_encrypt(msg, pub)
    plain = elgamal_decrypt(cipher, priv)
    assert plain == msg