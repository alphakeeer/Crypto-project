"""
简单基准脚本  
用法示例：
    python benchmark.py --alg rsa --bits 512 1024
"""

from __future__ import annotations

import argparse
import time
from typing import List

import pandas as pd
from crypto import (
    generate_rsa_keypair,
    rsa_encrypt,
    rsa_decrypt,
    generate_elgamal_keypair,
    elgamal_encrypt,
    elgamal_decrypt,
)


def benchmark_algorithm(alg: str, bits: List[int], repeats: int = 5) -> pd.DataFrame:
    """
    统计 keygen / enc / dec 平均耗时（秒）
    同时输出可视化结果
    """
    pass


def _rsa_ops(size: int) -> None:
    """内部：RSA 单次 keygen+enc+dec；计时用"""
    pass


def _elgamal_ops(size: int) -> None:
    """内部：ElGamal 单次 keygen+enc+dec；计时用"""
    pass


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--alg", choices=["rsa", "elgamal"], required=True)
    parser.add_argument("--bits", type=int, nargs="+", default=[512, 1024, 2048])
    args = parser.parse_args()

    df = benchmark_algorithm(args.alg, args.bits)
    print(df.to_markdown())


if __name__ == "__main__":
    main()