"""
RSA 公钥密码系统  
核心流程：密钥生成 → 加密 / 解密 → 签名 / 验签
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple
import math
import random
import hashlib

from .primes import *
from .utils import *

# ─────────────────────── 数据结构 ────────────────────────


@dataclass(slots=True)
class RSAPublicKey:
    """RSA 公钥 (e, n)"""
    e: int
    n: int


@dataclass(slots=True)
class RSAPrivateKey:
    """RSA 私钥 (d, n, p, q)"""
    d: int
    n: int
    p: int
    q: int


# ─────────────────────── 顶层 API ────────────────────────


def generate_keypair(bits: int = 2048) -> Tuple[RSAPublicKey, RSAPrivateKey]:
    """生成 RSA 密钥对

    Parameters
    ----------
    bits : int, default 2048
        模数 n 的位长，≥ 512

    Returns
    -------
    (RSAPublicKey, RSAPrivateKey)
    """
    if bits < 512:
        raise ValueError("密钥长度至少需要512位")

    p = generate_random_prime(bits // 2)
    q = generate_random_prime(bits // 2)

    while p == q:
        q = generate_random_prime(bits // 2)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    while math.gcd(e, phi) != 1:
        e = random.randint(3, phi - 1)

    d = modinv(e, phi)

    return RSAPublicKey(e=e, n=n), RSAPrivateKey(d=d, n=n, p=p, q=q)


def encrypt(msg: bytes, pub: RSAPublicKey, *, use_padding: bool = True) -> bytes:
    """RSA 加密

    - 若 `use_padding=True`，在加密前调用 utils.pad_pkcs1
    """
    n_bytes = (pub.n.bit_length() + 7) // 8

    if use_padding:
        padded_msg = pad_pkcs1(msg, n_bytes)
    else:
        if len(msg) > n_bytes:
            raise ValueError("消息太长无法加密")
        padded_msg = msg

    msg_int = int.from_bytes(padded_msg, byteorder='big')
    if msg_int >= pub.n:
        raise ValueError("消息太长无法加密")

    cipher_int = pow(msg_int, pub.e, pub.n)
    return cipher_int.to_bytes(n_bytes, byteorder='big')


def decrypt(cipher: bytes, priv: RSAPrivateKey, *, padded: bool = True) -> bytes:
    """RSA 解密

    - 若 `padded=True`，在解密后调用 utils.unpad_pkcs1
    """
    n_bytes = (priv.n.bit_length() + 7) // 8

    if len(cipher) != n_bytes:
        raise ValueError("密文长度不正确")

    cipher_int = int.from_bytes(cipher, byteorder='big')
    if cipher_int >= priv.n:
        raise ValueError("密文无效")

    msg_int = pow(cipher_int, priv.d, priv.n)
    msg = msg_int.to_bytes(n_bytes, byteorder='big')

    if padded:
        try:
            return unpad_pkcs1(msg)
        except ValueError as e:
            raise ValueError("解密失败: 无效的填充") from e
    else:
        return msg


def sign(digest: bytes, priv: RSAPrivateKey) -> bytes:
    """对摘要做 RSA 私钥签名（可选功能）"""
    n_bytes = (priv.n.bit_length() + 7) // 8

    if len(digest) > n_bytes - 11:
        raise ValueError("摘要太长无法签名")

    padded_digest = pad_pkcs1(digest, n_bytes)
    digest_int = int.from_bytes(padded_digest, byteorder='big')

    if digest_int >= priv.n:
        raise ValueError("填充后的摘要太长")

    sig_int = pow(digest_int, priv.d, priv.n)
    return sig_int.to_bytes(n_bytes, byteorder='big')


def verify(digest: bytes, sig: bytes, pub: RSAPublicKey) -> bool:
    """RSA 公钥验签

    Returns
    -------
    bool
        True → 验签通过；False → 失败
    """
    n_bytes = (pub.n.bit_length() + 7) // 8

    if len(sig) != n_bytes:
        return False

    try:
        sig_int = int.from_bytes(sig, byteorder='big')
        if sig_int >= pub.n:
            return False

        recovered_int = pow(sig_int, pub.e, pub.n)
        recovered_msg = recovered_int.to_bytes(n_bytes, byteorder='big')
        unpadded_msg = unpad_pkcs1(recovered_msg)
        return unpadded_msg == digest
    except:
        return False


def encrypt_long(msg: bytes, pub: RSAPublicKey) -> bytes:
    """RSA 长文本加密"""
    n_bytes = (pub.n.bit_length() + 7) // 8
    max_block_size = n_bytes - 11  # PKCS#1 v1.5 填充需要11字节

    if len(msg) <= max_block_size:
        return encrypt(msg, pub)

    # 分块加密
    cipher_blocks = []
    for i in range(0, len(msg), max_block_size):
        block = msg[i:i+max_block_size]
        cipher_blocks.append(encrypt(block, pub))

    return b''.join(cipher_blocks)


def decrypt_long(cipher: bytes, priv: RSAPrivateKey) -> bytes:
    """RSA 长文本解密"""
    n_bytes = (priv.n.bit_length() + 7) // 8

    if len(cipher) <= n_bytes:
        return decrypt(cipher, priv)

    # 分块解密
    msg_blocks = []
    for i in range(0, len(cipher), n_bytes):
        block = cipher[i:i+n_bytes]
        msg_blocks.append(decrypt(block, priv))

    return b''.join(msg_blocks)

# ─────────────────────── 测试代码 ────────────────────────


def test_rsa():
    print("测试RSA加密解密...")
    pub, priv = generate_keypair(1024)

    test_messages = [
        b"Hello RSA!",
        b"This is a test message.",
        b"Another message to test RSA encryption and decryption",
        ("这是一个非常长的测试消息，用来测试RSA的长文本加密功能。" * 50).encode('utf-8'),  # 约1500字节
        ("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum." * 20).encode('utf-8')  # 约2000字节的英文长文本
    ]

    for msg in test_messages:
        print(f"\n原始消息: {msg.decode('utf-8')}")

        # 根据消息长度选择使用普通加密还是长文本加密
        if len(msg) > 100:  # 长文本使用专门的加密函数
            cipher = encrypt_long(msg, pub)
            print(f"长文本加密后: {cipher.hex()}")
            decrypted = decrypt_long(cipher, priv)
            print(f"长文本解密后: {decrypted.decode('utf-8')}")
        else:
            cipher = encrypt(msg, pub)
            print(f"加密后: {cipher.hex()}")
            decrypted = decrypt(cipher, priv)
            print(f"解密后: {decrypted.decode('utf-8')}")
        assert decrypted == msg, "解密失败!"

        digest = hashlib.sha256(msg).digest()
        signature = sign(digest, priv)
        print(f"签名: {signature.hex()}")
        is_valid = verify(digest, signature, pub)
        print(f"验证结果: {'成功' if is_valid else '失败'}")
        assert is_valid, "验证失败!"


if __name__ == "__main__":
    test_rsa()
