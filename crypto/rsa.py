"""
RSA 公钥密码系统  
核心流程：密钥生成 → 加密 / 解密 → 签名 / 验签
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple

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
    pass


def encrypt(msg: bytes, pub: RSAPublicKey, *, use_padding: bool = True) -> bytes:
    """RSA 加密

    - 若 `use_padding=True`，在加密前调用 utils.pad_pkcs1
    """
    pass


def decrypt(cipher: bytes, priv: RSAPrivateKey, *, padded: bool = True) -> bytes:
    """RSA 解密

    - 若 `padded=True`，在解密后调用 utils.unpad_pkcs1
    """
    pass


def sign(digest: bytes, priv: RSAPrivateKey) -> bytes:
    """对摘要做 RSA 私钥签名（可选功能）"""
    pass


def verify(digest: bytes, sig: bytes, pub: RSAPublicKey) -> bool:
    """RSA 公钥验签

    Returns
    -------
    bool
        True → 验签通过；False → 失败
    """
    pass