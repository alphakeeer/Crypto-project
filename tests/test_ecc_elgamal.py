import os
import hashlib
import secrets
import pytest

from ecc_elgamal import (
    ECCElGamalPublicKey,
    ECCElGamalPrivateKey,
    generate_keypair,
    encrypt,
    decrypt,
    encrypt_file,
    decrypt_file,
    _p, _a, _b,
)

# --------------- 辅助校验函数 ---------------
def is_on_curve(x: int, y: int) -> bool:
    """检查 (x,y) 是否满足 y^2 ≡ x^3 + a·x + b (mod p)"""
    return (y * y - (x * x * x + _a * x + _b)) % _p == 0

# --------------- 测试密钥对 ---------------
def test_generate_keypair_structure():
    """生成的公私钥结构是否正确，且公钥点在曲线上"""
    pub, priv = generate_keypair()
    assert isinstance(pub, ECCElGamalPublicKey)
    assert isinstance(priv, ECCElGamalPrivateKey)
    # 公钥点必须在曲线上
    assert is_on_curve(pub.Qx, pub.Qy)

# --------------- 加解密轮测 ---------------
@pytest.mark.parametrize("msg", [
    b"",                                 # 空消息
    b"short",                            # 短消息
    secrets.token_bytes(1),              # 1 字节
    secrets.token_bytes(31),             # 31 字节（<单块 KDF 输出）
    secrets.token_bytes(32),             # 32 字节（=单块 KDF 输出）
    secrets.token_bytes(100),            # 多块输出
    b"\x00" * 50 + b"mixed\xff\xab",     # 包含 0x00 和随机字节
])
def test_encrypt_decrypt_roundtrip(msg):
    """各种长度消息加解密应当一致"""
    pub, priv = generate_keypair()
    R, ct = encrypt(msg, pub)
    rec = decrypt(R, ct, priv)
    assert rec == msg

# --------------- 文件加解密测试 ---------------
def test_encrypt_decrypt_file(tmp_path):
    """encrypt_file/decrypt_file 读写测试"""
    pub, priv = generate_keypair()
    # 准备明文文件
    pt = tmp_path / "pt.bin"
    data = b"File I/O test: ECC-ElGamal!"
    pt.write_bytes(data)

    # 加密
    ct = tmp_path / "ct.txt"
    encrypt_file(str(pt), str(ct), pub)
    assert ct.exists()
    lines = ct.read_text().splitlines()
    # 第一行应包含两段 hex，用 '|' 分隔
    assert "|" in lines[0] and len(lines) == 2

    # 解密
    out = tmp_path / "out.bin"
    decrypt_file(str(ct), str(out), priv)
    assert out.read_bytes() == data

# --------------- 参数化测试：多次密钥 ---------------
@pytest.mark.parametrize("n", [1, 2, 5])
def test_multiple_keypairs(n):
    """多次生成密钥对，各对公钥私钥应互不相同"""
    pairs = [generate_keypair() for _ in range(n)]
    # 提取每个公钥 (Qx,Qy)
    q_pts = {(pub.Qx, pub.Qy) for pub, _ in pairs}
    assert len(q_pts) == n

# --------------- 异常情况 ---------------
def test_decrypt_with_wrong_R_or_key():
    """使用错误的 R 或 私钥 解密不会得到原文"""
    pub, priv = generate_keypair()
    msg = b"Edge case"
    R, ct = encrypt(msg, pub)

    # 用随机 R' 解密，应得伪数据但不等于原文
    fake_R = (secrets.randbelow(_p), secrets.randbelow(_p))
    bad = decrypt(fake_R, ct, priv)
    assert bad != msg

    # 用正确 R，但用随机私钥解密
    fake_priv = ECCElGamalPrivateKey(d=secrets.randbelow(_p))
    bad2 = decrypt(R, ct, fake_priv)
    assert bad2 != msg

# --------------- 策略覆盖 ---------------
def test_kdf_expand_length_consistency():
    """测试内部 KDF 扩展函数在不同长度下工作正常"""
    # 直接调用内部接口，确保可用且长度准确
    from ecc_elgamal import _kdf_expand
    for length in [1, 32, 33, 100, 256]:
        out = _kdf_expand(123456789, length)
        assert isinstance(out, bytes)
        assert len(out) == length

