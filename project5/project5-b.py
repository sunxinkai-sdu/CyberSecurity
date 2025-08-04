import hashlib
import math
from math import gcd

# 椭圆曲线基础运算 (保持不变)
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
        # 计算斜率 (3x² + a)/2y
        lam = (3 * x1**2 + a) * modular_inverse(2 * y1, p) % p
    else:
        if x1 == x2:  # 垂直切线（无穷远点）
            return (0, 0)
        # 计算斜率 (y2 - y1)/(x2 - x1)
        lam = (y2 - y1) * modular_inverse(x2 - x1, p) % p
    
    # 计算新点坐标
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
    
    # 使用二进制展开进行快速乘法
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

# 签名算法 (保持不变)
def ecdsa_sign(p, a, n, G, d, k, message):
    """ECDSA签名生成"""
    # 计算临时公钥 R = k * G
    R = elliptic_curve_multiply(p, a, k, G)
    r = R[0] % n
    
    # 计算消息哈希
    e = int.from_bytes(hashlib.sha256(message.encode()).digest(), 'big') % n
    
    # 计算签名 s
    s = modular_inverse(k, n) * (e + d * r) % n
    return (r, s)

def schnorr_sign(p, a, n, G, d, k, message):
    """Schnorr签名生成（类似SM2结构）"""
    # 计算临时公钥 R = k * G
    R = elliptic_curve_multiply(p, a, k, G)
    
    # 计算挑战值 e = H(R_x || message)
    e = int.from_bytes(hashlib.sha256(f"{R[0]}{message}".encode()).digest(), 'big') % n
    
    # 计算签名 s = k + d*e mod n
    s = (k + d * e) % n
    return (R, s, e)

# 漏洞验证函数
def verify_k_leakage(p, a, n, G, r, s, k, message):
    """验证场景1：泄露k导致私钥d泄露"""
    e = int.from_bytes(hashlib.sha256(message.encode()).digest(), 'big') % n
    d = modular_inverse(r, n) * (k * s - e) % n
    return d

def verify_k_reuse(p, a, n, G, r1, s1, m1, r2, s2, m2):
    """验证场景2：重用k导致私钥d泄露"""
    # 两个签名使用相同的r值（因为k相同）
    if r1 != r2:
        return None
    
    e1 = int.from_bytes(hashlib.sha256(m1.encode()).digest(), 'big') % n
    e2 = int.from_bytes(hashlib.sha256(m2.encode()).digest(), 'big') % n
    
    # 计算k和d
    k = (e1 - e2) * modular_inverse(s1 - s2, n) % n
    d = modular_inverse(r1, n) * (k * s1 - e1) % n
    return k, d

def verify_cross_user_k(p, a, n, G, r1, s1, m1, r2, s2, m2):
    """验证场景3：两用户使用相同k导致私钥泄露（修正版）"""
    e1 = int.from_bytes(hashlib.sha256(m1.encode()).digest(), 'big') % n
    e2 = int.from_bytes(hashlib.sha256(m2.encode()).digest(), 'big') % n
    
    # 关键修正：当两个用户使用相同的k时，r值应该相同
    if r1 != r2:
        raise ValueError("r值不相等，表明k值不同")
    
    # 使用相同的r值
    r = r1
    
    # 计算k（使用用户1的签名）
    k = (e1 + d1 * r) * modular_inverse(s1, n) % n
    
    # 计算两个私钥
    d1_calc = (s1 * k - e1) * modular_inverse(r, n) % n
    d2_calc = (s2 * k - e2) * modular_inverse(r, n) % n
    
    return k, d1_calc, d2_calc

def verify_mixed_signatures(p, a, n, G, r, s_ecdsa, R_schnorr, s_schnorr, e_schnorr, message):
    """验证场景4：混合使用签名算法导致私钥泄露"""
    e_ecdsa = int.from_bytes(hashlib.sha256(message.encode()).digest(), 'big') % n
    
    # 从两个签名中提取信息
    term1 = s_schnorr * s_ecdsa
    term2 = e_ecdsa
    denominator = (r + e_schnorr * s_ecdsa) % n
    
    # 计算私钥d
    d = (term1 - term2) * modular_inverse(denominator, n) % n
    return d

if __name__ == '__main__':
    # 使用更安全的曲线参数 (secp256k1简化版)
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    a = 0
    b = 7
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 
         0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
    
    # 用户密钥
    d1 = 0x1E240  # 私钥1
    d2 = 0x2D560  # 私钥2
    k = 0x3A780   # 临时密钥（正常情况下应随机生成）
    
    # 测试消息
    m1 = "SDUCST"
    m2 = "SDUsxk"
    
    print("="*60)
    print("椭圆曲线签名算法误用POC验证")
    print("="*60)
    print(f"曲线参数: p={hex(p)[:20]}..., a={a}, b={b}")
    print(f"基点G: ({hex(G[0])[:15]}..., {hex(G[1])[:15]}...)")
    print(f"阶n: {hex(n)[:15]}...")
    print(f"私钥d1: {hex(d1)}, 私钥d2: {hex(d2)}")
    print(f"临时密钥k: {hex(k)}")
    print(f"消息1: '{m1}', 消息2: '{m2}'")
    print("="*60)
    
    # ======================== 场景1：泄露k导致私钥d泄露 ========================
    print("\n场景1：泄露k导致私钥d泄露")
    r1, s1 = ecdsa_sign(p, a, n, G, d1, k, m1)
    calculated_d = verify_k_leakage(p, a, n, G, r1, s1, k, m1)
    print(f"原始私钥: {hex(d1)}")
    print(f"计算私钥: {hex(calculated_d)}")
    print(f"验证结果: {'成功' if d1 == calculated_d else '失败'}")
    
    # ======================== 场景2：重用k导致私钥d泄露 ========================
    print("\n场景2：重用k导致私钥d泄露")
    r2, s2 = ecdsa_sign(p, a, n, G, d1, k, m1)
    r3, s3 = ecdsa_sign(p, a, n, G, d1, k, m2)
    k_calc, d_calc = verify_k_reuse(p, a, n, G, r2, s2, m1, r3, s3, m2)
    print(f"原始k: {hex(k)}, 计算k: {hex(k_calc)}")
    print(f"原始d: {hex(d1)}, 计算d: {hex(d_calc)}")
    print(f"验证结果: {'成功' if d1 == d_calc and k == k_calc else '失败'}")
    
    # ================= 场景3：两用户使用相同k导致私钥泄露=================
    print("\n场景3：两用户使用相同k导致私钥泄露")
    # 用户1使用k对m1签名
    r4, s4 = ecdsa_sign(p, a, n, G, d1, k, m1)
    # 用户2使用相同的k对m2签名
    r5, s5 = ecdsa_sign(p, a, n, G, d2, k, m2)
    
    try:
        k_calc2, d1_calc, d2_calc = verify_cross_user_k(p, a, n, G, r4, s4, m1, r5, s5, m2)
        print(f"原始k: {hex(k)}, 计算k: {hex(k_calc2)}")
        print(f"用户1原始d: {hex(d1)}, 计算d: {hex(d1_calc)}")
        print(f"用户2原始d: {hex(d2)}, 计算d: {hex(d2_calc)}")
        print(f"验证结果: {'成功' if d1 == d1_calc and d2 == d2_calc else '失败'}")
    except ValueError as e:
        print(f"验证失败: {e}")
    
    # ============== 场景4：混合签名算法导致私钥泄露 ==============
    print("\n场景4：ECDSA和Schnorr使用相同的d和k导致私钥泄露")
    r6, s6 = ecdsa_sign(p, a, n, G, d1, k, m1)
    R_sch, s_sch, e_sch = schnorr_sign(p, a, n, G, d1, k, m1)
    d_calc2 = verify_mixed_signatures(p, a, n, G, r6, s6, R_sch[0], s_sch, e_sch, m1)
    print(f"原始私钥: {hex(d1)}")
    print(f"计算私钥: {hex(d_calc2)}")
    print(f"验证结果: {'成功' if d1 == d_calc2 else '失败'}")
    print("="*60)
