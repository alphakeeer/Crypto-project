"""
ElGamal 公钥密码系统（乘法群版）
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple


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


def generate_keypair(bits: int = 2048) -> Tuple[ElGamalPublicKey, ElGamalPrivateKey]:
    """生成 ElGamal 密钥对"""
    pass


def encrypt(msg: bytes, pub: ElGamalPublicKey) -> Tuple[int, int, List[int]]:
    """ElGamal 加密

    Returns
    -------
    (c1, c2, blocks)
        c1 = g^k mod p  
        c2 = h^k mod p  
        blocks = 分块后的密文整数列表
    """
    pass


def decrypt(
    cipher: Tuple[int, int, List[int]],
    priv: ElGamalPrivateKey,
) -> bytes:
    """ElGamal 解密"""
    pass