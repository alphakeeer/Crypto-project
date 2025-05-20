"""
简单基准脚本  
用法示例：
    python benchmark.py --alg rsa --bits 512 1024
    python benchmark.py --alg elgamal --bits 512 1024
    python benchmark.py --alg ecc
"""

from __future__ import annotations

import argparse
import time
from typing import List
import pandas as pd
import random
import string
from crypto import (
    generate_rsa_keypair,
    rsa_encrypt,
    rsa_decrypt,
    generate_elgamal_keypair,
    elgamal_encrypt,
    elgamal_decrypt,
    generate_ecc_elgamal_keypair,
    ecc_elgamal_encrypt,
    ecc_elgamal_decrypt,
)


def benchmark_algorithm(alg: str, bits: List[int], repeats: int = 5) -> pd.DataFrame:
    """
    统计 keygen / enc / dec 平均耗时（秒）
    同时输出可视化结果
    """
    results = []
    print(f"开始对 {alg} 算法进行基准测试，位长列表: {bits}，重复次数: {repeats}")
    total_correct = 1
    if alg == 'ecc':
        print("正在处理 ECC 数据...")
        total_keygen_time = 0
        total_enc_time = 0
        total_dec_time = 0

        for i in range(repeats):
            print(f"  第 {i + 1} 次重复...")
            keygen_time, enc_time, dec_time, is_success = ecc_ops()
            total_keygen_time += keygen_time
            total_enc_time += enc_time
            total_dec_time += dec_time
            if not is_success:
                total_correct = 0
                print(f"  第 {i + 1} 次重复失败，ECC 数据处理失败。")
                break

        avg_keygen_time = total_keygen_time / repeats
        avg_enc_time = total_enc_time / repeats
        avg_dec_time = total_dec_time / repeats

        results.append({
            'Algorithm': alg,
            'Key Generation Time (s)': avg_keygen_time,
            'Encryption Time (s)': avg_enc_time,
            'Decryption Time (s)': avg_dec_time
        })
        if total_correct == 0:
            print(f"  {alg} 数据处理方法失败。")
            return pd.DataFrame(), 0
        print(f"{alg} 算法基准测试完成。")
        df = pd.DataFrame(results)
        return df, 1

    else:
        for bit_size in bits:
            print(f"正在处理位长 {bit_size} 的数据...")
            total_keygen_time = 0
            total_enc_time = 0
            total_dec_time = 0

            for i in range(repeats):
                print(f"  第 {i + 1} 次重复...")
                if alg == 'rsa':
                    keygen_time, enc_time, dec_time, is_success = _rsa_ops(bit_size)
                elif alg == 'elgamal':
                    keygen_time, enc_time, dec_time, is_success = _elgamal_ops(bit_size)
                else:
                    raise ValueError(f"不支持的算法: {alg}")

                total_keygen_time += keygen_time
                total_enc_time += enc_time
                total_dec_time += dec_time
                if not is_success:
                    total_correct = 0
                    print(f"  第 {i + 1} 次重复失败，位长 {bit_size} 的数据处理失败。")
                    break

            avg_keygen_time = total_keygen_time / repeats
            avg_enc_time = total_enc_time / repeats
            avg_dec_time = total_dec_time / repeats

            results.append({
                'Algorithm': alg,
                'Bit Size': bit_size,
                'Key Generation Time (s)': avg_keygen_time,
                'Encryption Time (s)': avg_enc_time,
                'Decryption Time (s)': avg_dec_time
            })
            print(f"  位长 {bit_size} 的数据处理完成。")
        if total_correct == 0:
            print(f"  {alg} 数据处理方法失败。")
            return pd.DataFrame(), 0
        print(f"{alg} 算法基准测试完成。")
        df = pd.DataFrame(results)
        return df, 1


def _rsa_ops(size: int) -> tuple[float, float, float, bool]:
    """内部：RSA 单次 keygen+enc+dec；计时用"""
    print(f"  开始 RSA 密钥生成，位长: {size}")
    # 记录密钥生成开始时间
    start_keygen = time.time()
    pub, priv = generate_rsa_keypair(size)
    keygen_time = time.time() - start_keygen
    print(f"  RSA 密钥生成完成，耗时: {keygen_time:.6f} 秒")

    # 准备测试消息
    msg = ''.join(random.choices(string.ascii_letters + string.digits, k=10000)).encode()

    print(f"  开始 RSA 加密，位长: {size}")
    # 记录加密开始时间
    start_enc = time.time()
    cipher = rsa_encrypt(msg, pub)
    enc_time = time.time() - start_enc
    print(f"  RSA 加密完成，耗时: {enc_time:.6f} 秒")

    print(f"  开始 RSA 解密，位长: {size}")
    # 记录解密开始时间
    start_dec = time.time()
    decrypted = rsa_decrypt(cipher, priv)
    dec_time = time.time() - start_dec
    print(f"  RSA 解密完成，耗时: {dec_time:.6f} 秒")
    is_success = decrypted == msg

    return keygen_time, enc_time, dec_time, is_success


def _elgamal_ops(size: int) -> tuple[float, float, float, bool]:
    """内部：ElGamal 单次 keygen+enc+dec；计时用"""
    print(f"  开始 ElGamal 密钥生成，位长: {size}")
    # 记录密钥生成开始时间
    start_keygen = time.time()
    pub, priv = generate_elgamal_keypair(size)
    keygen_time = time.time() - start_keygen
    print(f"  ElGamal 密钥生成完成，耗时: {keygen_time:.6f} 秒")

    # 准备测试消息
    msg = ''.join(random.choices(string.ascii_letters + string.digits, k=10000)).encode()

    print(f"  开始 ElGamal 加密，位长: {size}")
    # 记录加密开始时间
    start_enc = time.time()
    cipher = elgamal_encrypt(msg, pub)
    enc_time = time.time() - start_enc
    print(f"  ElGamal 加密完成，耗时: {enc_time:.6f} 秒")

    print(f"  开始 ElGamal 解密，位长: {size}")
    # 记录解密开始时间
    start_dec = time.time()
    decrypted = elgamal_decrypt(cipher, priv)
    dec_time = time.time() - start_dec
    print(f"  ElGamal 解密完成，耗时: {dec_time:.6f} 秒")
    is_success = decrypted == msg

    return keygen_time, enc_time, dec_time, is_success


def ecc_ops() -> tuple[float, float, float, bool]:
    """内部：ECC 单次 keygen+enc+dec；计时用"""
    print(f"  开始 ECC 密钥生成")
    # 记录密钥生成开始时间
    start_keygen = time.time()
    pub, priv = generate_ecc_elgamal_keypair()
    keygen_time = time.time() - start_keygen
    print(f"  ECC 密钥生成完成，耗时: {keygen_time:.6f} 秒")

    # 准备测试消息
    msg = ''.join(random.choices(string.ascii_letters + string.digits, k=10000)).encode()

    print(f"  开始 ECC 加密")
    # 记录加密开始时间
    start_enc = time.time()
    R, cipher = ecc_elgamal_encrypt(msg, pub)
    enc_time = time.time() - start_enc
    print(f"  ECC 加密完成，耗时: {enc_time:.6f} 秒")

    print(f"  开始 ECC 解密")
    # 记录解密开始时间
    start_dec = time.time()
    decrypted = ecc_elgamal_decrypt(R, cipher, priv)
    dec_time = time.time() - start_dec
    print(f"  ECC 解密完成，耗时: {dec_time:.6f} 秒")
    is_success = decrypted == msg

    return keygen_time, enc_time, dec_time, is_success


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--alg", choices=["rsa", "elgamal", "ecc"], required=True)
    parser.add_argument("--bits", type=int, nargs="+", default=[512, 1024, 2048])
    args = parser.parse_args()

    df, total_success = benchmark_algorithm(args.alg, args.bits)
    if total_success == 0:
        return
    print(df.to_markdown())


if __name__ == "__main__":
    main()
