"""
素数工具
========
实现​ Miller-Rabin 概率素性测试及相关高层封装。
"""

from __future__ import annotations

import random
from typing import List, Sequence
from functools import lru_cache
import secrets
import math

# 一组小素数，用于快速试除
# 首先预计算 1000 以内所有素数，供快速试除
@lru_cache(maxsize=1)
def _small_primes() -> Sequence[int]:
    sieve = bytearray([1]) * 1000
    sieve[0:2] = b'\x00\x00'
    for i in range(2, int(math.isqrt(999)) + 1):
        if sieve[i]:
            sieve[i*i :: i] = b'\x00' * ((999 - i*i) // i + 1)
    return tuple(i for i, is_p in enumerate(sieve) if is_p)

_SMALL_PRIMES = _small_primes()



def _miller_rabin(n: int, rounds: int) -> bool:
    """对 *奇整数* n 做 `rounds` 次随机 Miller-Rabin；rounds ≥ 1"""
    # 写成 n-1 = 2^s * d
    d, s = n - 1, 0
    while d & 1 == 0:
        d >>= 1
        s += 1

    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2  # a ∈ [2, n-2]
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for __ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False
    return True

def is_prime(n: int, *, rounds: int | None = 40) -> bool:
    """
    快速判断 n 是否为素数  
    - 先做极简取模过滤 (n%6∈{1,5})  
    - 再试除全部 `_SMALL_PRIMES`  
    - 对 2⁶⁴ 以下的 n 用确定性基底；否则随机做 `rounds` 轮 Miller-Rabin
    """
    if n in (2, 3):
        return True
    if n < 2 or n & 1 == 0 or n % 3 == 0:
        return False
    if n < 25:               # 到这一步只可能是 5,7,11,13,17,19,23
        return n in (5, 7, 11, 13, 17, 19, 23)

    # n % 6 必须在 {1,5}，否则一定合数（≈17% 数字直接出局）
    if n % 6 not in (1, 5):
        return False

    # 试除小素数
    for p in _SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False

    # 进入 Miller-Rabin
    if n.bit_length() <= 64:
        # < 2⁶⁴ 时用确定性基底集（Zimmermann 等人给出的最小集）
        for a in (2, 3, 5, 7, 11, 13, 17):
            if pow(a, n - 1, n) != 1:
                return False
        return True

    # 否则做随机轮；rounds=None ⇒ 使用默认 40 轮
    assert rounds is None or rounds >= 1, "`rounds` 必须 ≥1 或 None"
    return _miller_rabin(n, rounds or 40)

def generate_random_prime(bits: int, *, rounds: int = 40) -> int:
    """
    生成位长为 `bits` 的安全素数 p = 2q + 1，且 q 亦为素数  
    `rounds` 控制 Miller-Rabin 轮数（默认 40 ⇒ 误判概率 ≤ 2⁻⁸⁰）
    """
    if bits < 256:
        raise ValueError("bits 至少 256 才安全")

    while True:
        # 生成 (bits-1) 位奇数 q：最高、最低位皆为 1
        q = secrets.randbits(bits - 1) | (1 << (bits - 2)) | 1
        if not is_prime(q, rounds=rounds):
            continue
        p = (q << 1) + 1
        if is_prime(p, rounds=rounds):
            return p

def next_prime(n: int) -> int:
    """返回 ≥ n 的下一个素数

    Parameters
    ----------
    n : int
        基准整数

    Returns
    -------
    int
        向上最近的素数
    """
    if n < 2:
        return 2
    if n == 2:
        return 3
    if n & 1 == 0:
        n += 1

    # 从 n 开始，逐个加 2找奇数，直到找到素数
    while True:
        if is_prime(n):
            return n
        n += 2
