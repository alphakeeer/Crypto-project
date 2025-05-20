"""
椭圆曲线 ElGamal 公钥加密 —— ECC 版 ElGamal
"""

from __future__ import annotations

import secrets
import hashlib
from dataclasses import dataclass
from typing import Tuple

# ────────────────────────── 曲线参数（secp256k1） ─────────────
# y^2 = x^3 + a*x + b  over F_p
_p  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_a  = 0
_b  = 7
_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
_n  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# ────────────────────────── 数据结构 ──────────────────────────
@dataclass(slots=True)
class ECCElGamalPublicKey:
    """（曲线参数已隐含）公钥 Q = d·G"""
    Qx: int
    Qy: int

@dataclass(slots=True)
class ECCElGamalPrivateKey:
    """私钥 d"""
    d: int

# ────────────────────────── 辅助函数 ──────────────────────────
def _inv_mod(x: int, p: int) -> int:
    """模 p 的乘法逆元(p 为素数)"""
    return pow(x, p-2, p)

def _point_add(P: Tuple[int,int], Q: Tuple[int,int]) -> Tuple[int,int]:
    """椭圆曲线上的点加法，返回 P+Q"""
    if P is None: return Q
    if Q is None: return P
    x1,y1 = P; x2,y2 = Q
    if x1 == x2 and (y1 + y2) % _p == 0:
        return None
    if P != Q:
        lam = ((y2 - y1) * _inv_mod(x2 - x1, _p)) % _p
    else:
        lam = ((3 * x1 * x1 + _a) * _inv_mod(2 * y1, _p)) % _p
    x3 = (lam*lam - x1 - x2) % _p
    y3 = (lam*(x1 - x3) - y1) % _p
    return (x3, y3)

def _scalar_mul(k: int, P: Tuple[int,int]) -> Tuple[int,int]:
    """Double-and-add: 标量乘法 k·P"""
    R = None
    Q = P
    for bit in bin(k)[2:]:
        R = _point_add(R, R)
        if bit == '1':
            R = _point_add(R, Q)
    return R

def _kdf(x_coord: int) -> bytes:
    """简单 KDF: SHA256(x 坐标大端字节) → 32 字节密钥"""
    bx = x_coord.to_bytes((x_coord.bit_length()+7)//8, 'big')
    return hashlib.sha256(bx).digest()

def _kdf_expand(x_coord: int, outlen: int) -> bytes:
    """
    KDF 扩展：基于 SHA256，输出 outlen 字节
    """
    bx = x_coord.to_bytes((x_coord.bit_length()+7)//8, 'big')
    result = b''
    counter = 1
    while len(result) < outlen:
        hasher = hashlib.sha256()
        hasher.update(bx)
        hasher.update(counter.to_bytes(4, 'big'))
        result += hasher.digest()
        counter += 1
    return result[:outlen]

def _xor_bytes(a: bytes, b: bytes) -> bytes:
    """按位异或，长度按 a 截断"""
    return bytes(x ^ y for x,y in zip(a, b))

# ────────────────────────── 核心 API ──────────────────────────
def generate_keypair() -> Tuple[ECCElGamalPublicKey, ECCElGamalPrivateKey]:
    """
    生成 ECC-ElGamal 密钥对
    返回 (pub, priv)，其中 pub.Q = priv.d · G
    """
    d = secrets.randbelow(_n-1) + 1
    Q = _scalar_mul(d, (_Gx, _Gy))
    return ECCElGamalPublicKey(Qx=Q[0], Qy=Q[1]), ECCElGamalPrivateKey(d=d)

def encrypt(msg: bytes, pub: ECCElGamalPublicKey) -> Tuple[Tuple[int,int], bytes]:
    """
    ECC-ElGamal 加密
    • 输入 msg(二进制消息)、pub
    • 输出 (R_point, ciphertext)
        R_point = k·G
        ciphertext = msg ⊕ keystream(K), K = KDF(S.x), S = k·Q
    """
    # 随机会话密钥 k
    k = secrets.randbelow(_n-1) + 1
    R = _scalar_mul(k, (_Gx, _Gy))
    S = _scalar_mul(k, (pub.Qx, pub.Qy))
    # 生成足够长的伪随机流
    keystream = _kdf_expand(S[0], len(msg))
    ct = _xor_bytes(msg, keystream)
    return R, ct

def decrypt(R: Tuple[int,int], ct: bytes, priv: ECCElGamalPrivateKey) -> bytes:
    """
    ECC-ElGamal 解密
    • 输入 R_point、ciphertext、priv
    • 输出 原文 msg
    """
    S = _scalar_mul(priv.d, R)
    keystream = _kdf_expand(S[0], len(ct))
    msg = _xor_bytes(ct, keystream)
    return msg

# ────────────────────────── 文件读写 ──────────────────────────
def encrypt_file(in_path: str, out_path: str, pub: ECCElGamalPublicKey) -> None:
    with open(in_path, 'rb') as f:
        data = f.read()
    R, ct = encrypt(data, pub)
    # 写成文本两行：R.x|R.y|hex(ct)
    with open(out_path, 'w') as f:
        f.write(f"{R[0]:x}|{R[1]:x}\n")
        f.write(ct.hex())

def decrypt_file(in_path: str, out_path: str, priv: ECCElGamalPrivateKey) -> None:
    with open(in_path, 'r') as f:
        line = f.readline().strip()
        xs, ys = line.split('|')
        R = (int(xs, 16), int(ys, 16))
        ct = bytes.fromhex(f.read().strip())
    msg = decrypt(R, ct, priv)
    with open(out_path, 'wb') as f:
        f.write(msg)

# ────────────────────────── 示例 ──────────────────────────
if __name__ == "__main__":
    # 示例明文
    plaintext = b"Hello, ElGamal over elliptic curves!"

    # 1) 生成密钥对（这里不需要传参，默认 secp256k1）
    pub, priv = generate_keypair()

    # 2) 加密
    R, ciphertext = encrypt(plaintext, pub)

    # 3) 解密
    recovered = decrypt(R, ciphertext, priv)

    # 4) 打印结果并校验
    print("明文:   ", plaintext)
    print("解密:   ", recovered)
    print("成功:   ", plaintext == recovered)
