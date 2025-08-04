import hashlib
import math
from math import gcd

# 椭圆曲线基础运算
def elliptic_curve_add(p, a, P, Q):
    """椭圆曲线点加算法"""
    if P == (0, 0):
        return Q
    if Q == (0, 0):
        return P
    
    x1, y1 = P
    x2, y2 = Q
    
    # 处理点加倍
    if P == Q:
        if y1 == 0:  # 无穷远点
            return (0, 0)
        lam = (3 * x1**2 + a) * modular_inverse(2 * y1, p) % p
    else:
        if x1 == x2:  # 垂直切线（无穷远点）
            return (0, 0)
        lam = (y2 - y1) * modular_inverse(x2 - x1, p) % p
    
    x3 = (lam**2 - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)

def elliptic_curve_multiply(p, a, n, point):
    """椭圆曲线标量乘法（快速倍点算法）"""
    if n == 0:
        return (0, 0)
    if n == 1:
        return point
    
    result = (0, 0)
    current = point
    
    while n:
        if n & 1:
            result = elliptic_curve_add(p, a, result, current)
        current = elliptic_curve_add(p, a, current, current)
        n >>= 1
    return result

def modular_inverse(a, m):
    """计算模逆元（扩展欧几里得算法）"""
    if gcd(a, m) != 1:
        return None
    
    old_r, r = a, m
    old_s, s = 1, 0
    
    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
    
    return old_s % m

def ecdsa_sign(p, a, n, G, d, k, message):
    """ECDSA签名生成"""
    R = elliptic_curve_multiply(p, a, k, G)
    r = R[0] % n
    e = int.from_bytes(hashlib.sha256(message.encode()).digest(), 'big') % n
    s = modular_inverse(k, n) * (e + d * r) % n
    return (r, s)

def verify_signature(p, a, n, G, pub_key, message, signature):
    """验证ECDSA签名"""
    r, s = signature
    if not (1 <= r < n and 1 <= s < n):
        return False
    
    e = int.from_bytes(hashlib.sha256(message.encode()).digest(), 'big') % n
    w = modular_inverse(s, n)
    u1 = (e * w) % n
    u2 = (r * w) % n
    
    # 计算点 P = u1*G + u2*Q
    P1 = elliptic_curve_multiply(p, a, u1, G)
    P2 = elliptic_curve_multiply(p, a, u2, pub_key)
    P = elliptic_curve_add(p, a, P1, P2)
    
    return P != (0, 0) and P[0] % n == r

def forge_satoshi_signature():
    """伪造中本聪签名的演示"""
    # 比特币使用的secp256k1曲线参数
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    a = 0
    b = 7
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 
         0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
    
    # 假设我们获取了中本聪的两个真实签名（使用相同的k）
    # 这些签名可以从区块链交易历史中获取
    message1 = "2009年1月3日，财政大臣正处于实施第二轮银行紧急援助的边缘"
    message2 = "创世区块奖励50BTC"
    
    # 中本聪的私钥（实际未知，这里仅用于生成演示签名）
    satoshi_d = 0x18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725
    k = 0x3A780  # 重复使用的k值
    
    # 生成两个真实签名
    sig1 = ecdsa_sign(p, a, n, G, satoshi_d, k, message1)
    sig2 = ecdsa_sign(p, a, n, G, satoshi_d, k, message2)
    
    print("="*70)
    print("伪造中本聪数字签名演示")
    print("="*70)
    print(f"消息1: '{message1}'")
    print(f"签名1: (r={hex(sig1[0])}, s={hex(sig1[1])})")
    print(f"\n消息2: '{message2}'")
    print(f"签名2: (r={hex(sig2[0])}, s={hex(sig2[1])})")
    print("\n分析：两个签名使用了相同的随机数k（r值相同）")
    
    # 从签名中恢复k和私钥
    r1, s1 = sig1
    r2, s2 = sig2
    
    # 验证r值是否相同（k重复使用的标志）
    if r1 != r2:
        print("错误：签名没有使用相同的k值")
        return
    
    # 计算消息哈希
    e1 = int.from_bytes(hashlib.sha256(message1.encode()).digest(), 'big') % n
    e2 = int.from_bytes(hashlib.sha256(message2.encode()).digest(), 'big') % n
    
    # 计算k
    k_calculated = (e1 - e2) * modular_inverse(s1 - s2, n) % n
    
    # 计算私钥
    d_calculated = modular_inverse(r1, n) * (k_calculated * s1 - e1) % n
    
    print("\n通过签名分析恢复的信息：")
    print(f"恢复的随机数k: {hex(k_calculated)}")
    print(f"恢复的中本聪私钥: {hex(d_calculated)}")
    
    # 验证恢复的私钥是否正确
    if d_calculated == satoshi_d:
        print("\n成功恢复中本聪的私钥！")
    else:
        print("\n私钥恢复失败")
        return
    
    # 使用恢复的私钥伪造新签名
    forged_message = "我决定将100万BTC转移给演示者"
    forged_signature = ecdsa_sign(p, a, n, G, d_calculated, k_calculated, forged_message)
    
    # 验证伪造的签名
    # 计算中本聪的公钥（用于验证）
    satoshi_pub = elliptic_curve_multiply(p, a, satoshi_d, G)
    
    is_valid = verify_signature(p, a, n, G, satoshi_pub, forged_message, forged_signature)
    
    print("\n伪造新签名：")
    print(f"伪造的消息: '{forged_message}'")
    print(f"伪造的签名: (r={hex(forged_signature[0])}, s={hex(forged_signature[1])})")
    print(f"\n签名验证结果: {'有效' if is_valid else '无效'}")
    
    if is_valid:
        print("\n成功伪造中本聪的数字签名！")
        print("注意：在真实比特币网络中，这个签名将被视为有效交易")
    else:
        print("\n签名伪造失败")
    
    print("="*70)

if __name__ == '__main__':
    forge_satoshi_signature()
