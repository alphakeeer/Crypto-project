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
    rsa_encrypt_long,
    rsa_decrypt_long,
)


def test_encrypt_decrypt_roundtrip() -> None:
    """随机消息加解密应一致"""
    pub, priv = generate_rsa_keypair(512)
    msg = random.randbytes(32) if hasattr(
        random, "randbytes") else os.urandom(32)
    cipher = rsa_encrypt(msg, pub)
    plain = rsa_decrypt(cipher, priv)
    assert plain == msg


def test_empty_message() -> None:
    """测试空消息"""
    pub, priv = generate_rsa_keypair(512)
    msg = b""
    cipher = rsa_encrypt(msg, pub)
    plain = rsa_decrypt(cipher, priv)
    assert plain == msg


def test_max_length_message() -> None:
    """测试最大长度消息"""
    pub, priv = generate_rsa_keypair(512)
    n_bytes = (pub.n.bit_length() + 7) // 8
    max_len = n_bytes - 11  # PKCS#1填充需要11字节
    msg = b"A" * max_len
    cipher = rsa_encrypt(msg, pub)
    plain = rsa_decrypt(cipher, priv)
    assert plain == msg


def test_long_message() -> None:
    """测试长文本加密"""
    pub, priv = generate_rsa_keypair(512)
    msg = b"Long message " * 100  # 1300字节
    cipher = rsa_encrypt_long(msg, pub)
    plain = rsa_decrypt_long(cipher, priv)
    assert plain == msg


def test_invalid_input() -> None:
    """测试无效输入"""
    pub, priv = generate_rsa_keypair(512)
    n_bytes = (pub.n.bit_length() + 7) // 8
    max_len = n_bytes - 11

    # 测试过长的消息
    with pytest.raises(ValueError):
        rsa_encrypt(b"A" * (max_len + 1), pub)

    # 测试无效的密文
    with pytest.raises(ValueError):
        rsa_decrypt(b"invalid cipher", priv)


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
