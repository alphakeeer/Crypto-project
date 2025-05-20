"""
数学与字节序列辅助函数
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Tuple
import random

def gcd(a: int, b: int) -> int:
    """最大公约数"""
    if a==0:
        return b
    else:
        return gcd(b % a, a)

def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """扩展欧几里得算法"""
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = extended_gcd(b % a, a)
        return (g, x - (b // a) * y, y)

def lcm(a: int, b: int) -> int:
    """最小公倍数"""
    return a / gcd(a, b) * b


def modinv(a: int, m: int) -> int:
    """模反元素：求 a⁻¹ mod m，如不存在则抛异常"""
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise ValueError('模逆元不存在')
    return x % m
    


def bytes_to_int(data: bytes) -> int:
    """按大端序将字节串转换为整数"""
    return int.from_bytes(data, byteorder='big')


def int_to_bytes(n: int, length: int | None = None) -> bytes:
    """按大端序将整数转换为 **定长** 字节串

    若 `length` 为 None，则自动推断最短长度。
    """
    if length is None:
        length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, byteorder='big')


def pad_pkcs1(data: bytes, n_bytes: int) -> bytes:
    """PKCS#1 v1.5 填充"""
    if len(data) > n_bytes - 11:
        raise ValueError("数据太长无法填充")
    
    padding_length = n_bytes - len(data) - 3
    padding = bytes([random.randint(1, 255) for _ in range(padding_length)])
    
    return b'\x00\x02' + padding + b'\x00' + data


def unpad_pkcs1(padded_data: bytes) -> bytes:
    """PKCS#1 v1.5 去除填充"""
    if len(padded_data) < 11 or padded_data[0:2] != b'\x00\x02':
        raise ValueError("无效的PKCS#1填充")
    
    separator_pos = padded_data.find(b'\x00', 2)
    if separator_pos == -1:
        raise ValueError("无效的PKCS#1填充")
    
    return padded_data[separator_pos+1:]
