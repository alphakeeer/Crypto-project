"""
pytest 单元测试：RSA
"""

import os
import random

import pytest
from crypto import (
    generate_rsa_keypair,
    rsa_encrypt,
    rsa_decrypt,
    rsa_sign,
    rsa_verify,
)


def test_encrypt_decrypt_roundtrip() -> None:
    """随机消息加解密应一致"""
    pub, priv = generate_rsa_keypair(512)
    msg = random.randbytes(32) if hasattr(random, "randbytes") else os.urandom(32)
    cipher = rsa_encrypt(msg, pub)
    plain = rsa_decrypt(cipher, priv)
    assert plain == msg


def test_signature_verify() -> None:
    pub, priv = generate_rsa_keypair(512)
    digest = b"example sha256 digest"
    sig = rsa_sign(digest, priv)
    assert rsa_verify(digest, sig, pub)
    assert not rsa_verify(digest + b"tamper", sig, pub)


@pytest.mark.parametrize("bits", [512, 1024])
def test_key_sizes(bits: int) -> None:
    pub, priv = generate_rsa_keypair(bits)
    assert pub.n.bit_length() == bits