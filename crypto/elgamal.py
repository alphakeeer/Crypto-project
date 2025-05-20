"""
ElGamal 公钥密码系统（乘法群版）
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple

from primes import *
from utils import *


# ────────────────────────── 辅助结构 ──────────────────────────
def _find_primitive_root(p: int) -> int:
    """对于 safe prime p = 2q + 1，找生成元 g"""
    q = (p - 1) // 2
    while True:
        g = secrets.randbelow(p - 3) + 2        # g ∈ [2, p-2]
        if pow(g, 2, p) != 1 and pow(g, q, p) != 1:
            return g


# ────────────────────────── 数据结构 ──────────────────────────
@dataclass(slots=True)
class ElGamalPublicKey:
    """(p, g, h = g^x mod p)"""
    p: int
    g: int
    h: int


@dataclass(slots=True)
class ElGamalPrivateKey:
    """(p, g, x)"""
    p: int
    g: int
    x: int

# ────────────────────────── 核心算法 ──────────────────────────
def generate_keypair(bits: int = 2048) -> Tuple[ElGamalPublicKey, ElGamalPrivateKey]:
    """
    生成 ElGamal 密钥对
    bits : 素数 p 的位数（>=256；常用 2048/3072）  
    """
    p = generate_random_prime(bits)
    g = _find_primitive_root(p)
    x = secrets.randbelow(p - 3) + 2          # 私钥 x ∈ [2, p-2]
    h = pow(g, x, p)                          # 公钥 h = g^x mod p
    return ElGamalPublicKey(p, g, h), ElGamalPrivateKey(p, g, x)


def encrypt(msg: bytes, pub: ElGamalPublicKey) -> Tuple[int, int, List[int]]:
    """
    ElGamal 加密
    输出 (c1, c2, blocks)
      • c1 = g^k mod p
      • c2 = h^k mod p
      • blocks = 每个明文分块乘以 c2 后的整数列表
    """
    # ---- 分块 ----
    block_bytes = (pub.p.bit_length() - 1) // 8   # 每块 ≤ p-1
    if block_bytes == 0:
        raise ValueError("p 太小")
    blocks_int: List[int] = [
        int.from_bytes(msg[i : i + block_bytes], "big")
        for i in range(0, len(msg), block_bytes)
    ]

    # ---- 随机会话密钥 k ----
    k = secrets.randbelow(pub.p - 3) + 2           # k ∈ [2, p-2]
    c1 = pow(pub.g, k, pub.p)
    c2 = pow(pub.h, k, pub.p)                      # 共享密钥 s = h^k

    cipher_blocks = [(m * c2) % pub.p for m in blocks_int]
    return c1, c2, cipher_blocks


def decrypt(
    cipher: Tuple[int, int, List[int]],
    priv: ElGamalPrivateKey,
) -> bytes:
    """ElGamal 解密：无损还原明文"""
    c1, _c2_unused, cipher_blocks = cipher
    s = pow(c1, priv.x, priv.p)             # 会话密钥
    s_inv = pow(s, priv.p - 2, priv.p)      # 乘法逆元

    plain = bytearray()
    for c in cipher_blocks:
        m = (c * s_inv) % priv.p
        if m == 0:                          # 特例：整数 0 ⇒ 单字节 b'\x00'
            plain.extend(b"\x00")
        else:
            # 用 *最短* 字节串表示 m，避免首部补零
            plain.extend(m.to_bytes((m.bit_length() + 7) // 8, "big"))

    return bytes(plain)

if __name__ == "__main__":
    plaintext = b"Hello, ElGamal over multiplicative groups!"

    pub, priv = generate_keypair(512)  # 生成 1024 位示例密钥
    cipher = encrypt(plaintext, pub)
    recovered = decrypt(cipher, priv)

    print("明文:", plaintext)
    print("解密:", recovered)
    print("成功:", plaintext == recovered)