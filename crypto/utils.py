"""
数学与字节序列辅助函数
"""

from __future__ import annotations


def gcd(a: int, b: int) -> int:
    """最大公约数"""
    pass


def lcm(a: int, b: int) -> int:
    """最小公倍数"""
    pass


def modinv(a: int, m: int) -> int:
    """模反元素：求 a⁻¹ mod m，如不存在则抛异常"""
    pass


def bytes_to_int(data: bytes) -> int:
    """按大端序将字节串转换为整数"""
    pass


def int_to_bytes(n: int, length: int | None = None) -> bytes:
    """按大端序将整数转换为 **定长** 字节串

    若 `length` 为 None，则自动推断最短长度。
    """
    pass


def pad_pkcs1(msg: bytes, key_len: int) -> bytes:
    """PKCS#1 v1.5 填充（仅示例，生产环境请改用 OAEP）"""
    pass


def unpad_pkcs1(padded: bytes) -> bytes:
    """去除 PKCS#1 v1.5 填充；非法填充应抛异常"""
    pass