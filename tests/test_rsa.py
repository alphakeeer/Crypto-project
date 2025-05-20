"""
pytest 单元测试：RSA
"""

import os
import random
import math

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


def validate_rsa_keypair(pub_key, priv_key) -> bool:
    """验证RSA密钥对是否符合标准"""
    # 检查n是否一致
    if pub_key.n != priv_key.n:
        return False
    
    # 检查n = p * q
    if priv_key.p * priv_key.q != priv_key.n:
        return False
    
    # 检查e和d是模逆元
    phi = (priv_key.p - 1) * (priv_key.q - 1)
    if (pub_key.e * priv_key.d) % phi != 1:
        return False
    
    # 检查p和q是否为素数
    def is_prime(n):
        if n <= 1:
            return False
        for i in range(2, int(math.sqrt(n)) + 1):
            if n % i == 0:
                return False
        return True
    
    return is_prime(priv_key.p) and is_prime(priv_key.q)


def test_encrypt_decrypt_roundtrip() -> None:
    """随机消息加解密应一致"""
    pub, priv = generate_rsa_keypair(512)
    assert validate_rsa_keypair(pub, priv), "生成的密钥对无效"
    
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
    assert validate_rsa_keypair(pub, priv), "生成的密钥对无效"
    
    digest = b"example sha256 digest"
    sig = rsa_sign(digest, priv)
    assert rsa_verify(digest, sig, pub)
    assert not rsa_verify(digest + b"tamper", sig, pub)
    
    # 测试无效签名
    invalid_sig = bytes([(b + 1) % 256 for b in sig])
    assert not rsa_verify(digest, invalid_sig, pub)


@pytest.mark.parametrize("bits", [512, 1024, 2048])
def test_key_sizes(bits: int) -> None:
    pub, priv = generate_rsa_keypair(bits)
    assert pub.n.bit_length() == bits
    assert validate_rsa_keypair(pub, priv), "生成的密钥对无效"
    
def test_key_validation() -> None:
    """专门测试密钥验证函数"""
    pub, priv = generate_rsa_keypair(512)
    assert validate_rsa_keypair(pub, priv)
    
    # 测试无效密钥对
    from dataclasses import replace
    invalid_priv = replace(priv, d=priv.d+1)
    assert not validate_rsa_keypair(pub, invalid_priv)
