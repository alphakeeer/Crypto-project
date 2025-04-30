"""
crypto 顶层包

- 明确声明导出的公共 API（`__all__`）
- 将子模块常用函数 / 类转发到顶层，便于：
      from crypto import generate_rsa_keypair, rsa_encrypt
"""

from __future__ import annotations

# ↓ 扁平导入：顶层直接访问 RSA / ElGamal 的主要 API
from .rsa import (                       # type: ignore F401
    RSAPublicKey,
    RSAPrivateKey,
    generate_keypair as generate_rsa_keypair,
    encrypt as rsa_encrypt,
    decrypt as rsa_decrypt,
    sign as rsa_sign,
    verify as rsa_verify,
)
from .elgamal import (                   # type: ignore F401
    ElGamalPublicKey,
    ElGamalPrivateKey,
    generate_keypair as generate_elgamal_keypair,
    encrypt as elgamal_encrypt,
    decrypt as elgamal_decrypt,
)

__all__: list[str] = [
    # RSA
    "RSAPublicKey",
    "RSAPrivateKey",
    "generate_rsa_keypair",
    "rsa_encrypt",
    "rsa_decrypt",
    "rsa_sign",
    "rsa_verify",
    # ElGamal
    "ElGamalPublicKey",
    "ElGamalPrivateKey",
    "generate_elgamal_keypair",
    "elgamal_encrypt",
    "elgamal_decrypt",
]