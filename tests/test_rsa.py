"""
pytest 单元测试：RSA
覆盖率目标：≥90%
"""

import os
import random
import math
import hashlib
import pytest
from crypto import (  # 改为绝对导入
    RSAPublicKey,
    RSAPrivateKey,
    generate_keypair,
    encrypt,
    decrypt,
    sign,
    verify,
    encrypt_long,
    decrypt_long,
    pad_pkcs1,
    unpad_pkcs1,
)


def validate_rsa_keypair(pub_key: RSAPublicKey, priv_key: RSAPrivateKey) -> bool:
    """验证RSA密钥对是否符合标准"""
    # 检查n是否一致
    if pub_key.n != priv_key.n:
        return False
    
    # 检查n = p * q
    if priv_key.p * priv_key.q != priv_key.n:
        return False
    
    # 检查e和d是模逆元
    phi = (priv_key.p - 1) * (priv_key.q - 1)
    try:
        if (pub_key.e * priv_key.d) % phi != 1:
            return False
    except ValueError:
        return False
    
    # 检查p和q是否为素数
    def is_prime(n: int) -> bool:
        if n <= 1:
            return False
        if n == 2 or n == 3:
            return True
        if n % 2 == 0:
            return False
        d = n - 1
        s = 0
        while d % 2 == 0:
            d //= 2
            s += 1
        for _ in range(5):  # 5轮米勒-拉宾测试
            a = random.randint(2, n - 2)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for __ in range(s - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True
    
    return is_prime(priv_key.p) and is_prime(priv_key.q)


def encrypt_decrypt_roundtrip() -> None:
    """随机消息加解密应一致"""
    pub, priv = generate_keypair(512)
    assert validate_rsa_keypair(pub, priv), "生成的密钥对无效"
    
    msg = random.randbytes(32) if hasattr(
        random, "randbytes") else os.urandom(32)
    cipher = encrypt(msg, pub)
    plain = decrypt(cipher, priv)
    assert plain == msg


def test_empty_message() -> None:
    """测试空消息"""
    pub, priv = generate_keypair(512)
    msg = b""
    cipher = encrypt(msg, pub)
    plain = decrypt(cipher, priv)
    assert plain == msg


def test_max_length_message() -> None:
    """测试最大长度消息"""
    pub, priv = generate_keypair(512)
    n_bytes = (pub.n.bit_length() + 7) // 8
    max_len = n_bytes - 11  # PKCS#1填充需要11字节
    msg = b"A" * max_len
    cipher = encrypt(msg, pub)
    plain = decrypt(cipher, priv)
    assert plain == msg


def test_over_length_message() -> None:
    """测试超过最大长度的消息"""
    pub, priv = generate_keypair(512)
    n_bytes = (pub.n.bit_length() + 7) // 8
    max_len = n_bytes - 11
    with pytest.raises(ValueError):
        encrypt(b"A" * (max_len + 1), pub)


def test_padding() -> None:
    """测试PKCS#1填充和去填充"""
    n_bytes = 256  # 2048位密钥
    test_msg = b"Test message"
    
    # 测试填充
    padded = pad_pkcs1(test_msg, n_bytes)
    assert len(padded) == n_bytes
    assert padded.startswith(b'\x00\x02')
    assert b'\x00' in padded[2:]
    
    # 测试去填充
    unpadded = unpad_pkcs1(padded)
    assert unpadded == test_msg
    
    # 测试无效填充
    invalid_padded = b'\x00\x01' + b'\x00' + test_msg
    with pytest.raises(ValueError):
        unpad_pkcs1(invalid_padded)


def test_long_message() -> None:
    """测试长文本加密"""
    pub, priv = generate_keypair(512)
    msg = b"Long message " * 100  # 1300字节
    cipher = encrypt_long(msg, pub)
    plain = decrypt_long(cipher, priv)
    assert plain == msg
    
    
    # 测试无效的密文
    with pytest.raises(ValueError):
        decrypt(b"invalid cipher", priv)


def test_signature_verify() -> None:
    pub, priv = generate_keypair(512)
    assert validate_rsa_keypair(pub, priv), "生成的密钥对无效"
    
    digest = hashlib.sha256(b"example message").digest()
    sig = sign(digest, priv)
    assert verify(digest, sig, pub)
    assert not verify(digest + b"tamper", sig, pub)
    
    # 测试无效签名
    invalid_sig = bytes([(b + 1) % 256 for b in sig])
    assert not verify(digest, invalid_sig, pub)
    
    # 测试无效密钥
    other_pub, _ = generate_keypair(512)
    assert not verify(digest, sig, other_pub)


@pytest.mark.parametrize("bits", [512, 1024, 2048])
def test_key_sizes(bits: int) -> None:
    pub, priv = generate_keypair(bits)
    assert pub.n.bit_length() >= bits  # 允许略大于指定位数
    assert validate_rsa_keypair(pub, priv), "生成的密钥对无效"


def test_key_validation() -> None:
    """专门测试密钥验证函数"""
    pub, priv = generate_keypair(512)
    assert validate_rsa_keypair(pub, priv)
    
    # 测试无效密钥对
    from dataclasses import replace
    invalid_priv = replace(priv, d=priv.d+1)
    assert not validate_rsa_keypair(pub, invalid_priv)
    
    invalid_priv = replace(priv, p=priv.q)  # p == q
    assert not validate_rsa_keypair(pub, invalid_priv)


def test_encrypt_without_padding() -> None:
    """测试不使用填充的加密"""
    pub, priv = generate_keypair(512)
    n_bytes = (pub.n.bit_length() + 7) // 8
    msg = b"A" * (n_bytes - 1)  # 比n小1字节
    
    cipher = encrypt(msg, pub, use_padding=False)
    plain = decrypt(cipher, priv, padded=False)
    assert plain == msg
    
    # 测试超过n长度的消息
    with pytest.raises(ValueError):
        encrypt(b"A" * n_bytes, pub, use_padding=False)


def test_signature_edge_cases() -> None:
    """测试签名的边界情况"""
    pub, priv = generate_keypair(512)
    
    # 测试空摘要
    empty_digest = hashlib.sha256(b"").digest()
    sig = sign(empty_digest, priv)
    assert verify(empty_digest, sig, pub)
    
    # 测试最大长度摘要
    n_bytes = (pub.n.bit_length() + 7) // 8
    max_digest = b"A" * (n_bytes - 11)
    sig = sign(max_digest, priv)
    assert verify(max_digest, sig, pub)
    
    # 测试超过最大长度的摘要
    with pytest.raises(ValueError):
        sign(b"A" * (n_bytes - 10), priv)
