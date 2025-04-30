"""
素数工具
========
实现​ Miller-Rabin 概率素性测试及相关高层封装。
"""

from __future__ import annotations

import random


def is_prime(n: int) -> bool:
    """快速判断 n 是否为素数（封装 _miller_rabin 或简单试除）

    Parameters
    ----------
    n : int
        待测正整数

    Returns
    -------
    bool
        True 表示 n 极可能为素数，False 表示 n 为合数
    """
    # TODO: 简单小数试除 & 调用 _miller_rabin
    pass


def _miller_rabin(n: int, k: int) -> bool:
    """Miller–Rabin 素性测试（内部函数）

    Parameters
    ----------
    n : int
        奇整数，待测试
    k : int
        随机基底轮数，k 越大误判概率越低

    Returns
    -------
    bool
        True → 可能是素数；False → 一定为合数
    """
    pass


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
    pass


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