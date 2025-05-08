"""
素数工具
========
实现​ Miller-Rabin 概率素性测试及相关高层封装。
"""

from __future__ import annotations

import random
from typing import List


# 一组小素数，用于快速试除
_small_primes: List[int] = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
    31, 37, 41, 43, 47, 53, 59, 61, 67, 71
]

def is_prime(n: int) -> bool:
    """快速判断 n 是否为素数（先试除小素数，再调用 _miller_rabin）

    Parameters
    ----------
    n : int
        待测正整数

    Returns
    -------
    bool
        True 表示 n 极可能为素数，False 表示 n 为合数
    """
    # 小于 2 都不是素数
    if n < 2:
        return False

    # 对小素数列表做试除
    for p in _small_primes:
        if n == p:
            return True
        if n % p == 0:
            return False

    # 如果已经试除了列表中的所有小素数，则一定是奇数 > max(_small_primes)
    # 调用 Miller–Rabin 进行更大范围的检验
    return _miller_rabin(n)


def _miller_rabin(n: int, k: int = None) -> bool:
    """Miller–Rabin 素性测试（内部函数）

    若不指定 k，则使用针对 64 位整数的确定性基底，保证 64 位范围内零误判。

    Parameters
    ----------
    n : int
        奇整数，待测试（确保 n > max(_small_primes)，且 n 为奇数）
    k : int, optional
        随机基底轮数，k 越大误判概率越低；若为 None，则使用确定性基底。

    Returns
    -------
    bool
        True → 可能是素数；False → 一定为合数
    """
    # 分解 n-1 = d * 2^s，令 d 为奇数
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    def trial(a: int) -> bool:
        """针对单个基底 a 的一次测试"""
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            return True
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                return True
        return False

    # 如果用户指定了随机测试轮数 k，就随机选基底
    if k is not None:
        for _ in range(k):
            a = random.randrange(2, n - 1)
            if not trial(a):
                return False
        return True

    # 否则，使用已知的“确定性”基底集，可在 64 位整数范围内零误判
    # 参考：https://miller-rabin.appspot.com/ （常用基底集）
    deterministic_bases = [2, 325, 9375, 28178, 450775, 9780504, 1795265022]
    for a in deterministic_bases:
        if a % n == 0:
            # 基底 a 与 n 不互素，跳过
            continue
        if not trial(a):
            return False
    return True


def generate_random_prime(bits: int, k: int = 40) -> int:
    """生成一个指定位长的安全素数

    Parameters
    ----------
    bits : int
        位长（≥ 2）
    k : int, default 40
        Miller–Rabin 轮数

    Returns
    -------
    int
        随机安全素数 p
    """
    # TODO:未使用miller-rabin的k参数
    while True:
        num = random.getrandbits(bits)
        # 确保是奇数并且有正确的位数
        num |= (1 << bits - 1) | 1
        if is_prime(num):
            return num


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
    pass