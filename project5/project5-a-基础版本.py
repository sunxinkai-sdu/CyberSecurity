import math
import random
import time
import hashlib
import binascii

# 基础版本的SM3哈希算法实现
def sm3_hash(msg):
    """基础版SM3哈希算法实现"""
    # 初始化常量
    IV = "7380166f4914b2b9172442d7da8a0600a96f30bc163138aae38dee4db0fb0e4e"
    T = [0x79cc4519] * 16 + [0x7a879d8a] * 48
    
    # 消息填充
    msg_byte = msg if isinstance(msg, bytes) else msg.encode('utf-8')
    msg_len = len(msg_byte) * 8
    msg_byte += b'\x80'
    while (len(msg_byte) * 8) % 512 != 448:
        msg_byte += b'\x00'
    msg_byte += msg_len.to_bytes(8, 'big')
    
    # 处理消息分组
    blocks = [msg_byte[i:i+64] for i in range(0, len(msg_byte), 64)]
    V = [int(IV[i:i+8], 16) for i in range(0, len(IV), 8)]
    
    # 处理每个分组
    for block in blocks:
        # 消息扩展
        W = []
        for j in range(0, 16):
            W.append(int.from_bytes(block[j*4:j*4+4], 'big'))
        
        for j in range(16, 68):
            x = W[j-16] ^ W[j-9] ^ (rotate_left(W[j-3], 15))
            p1 = x ^ (rotate_left(x, 15)) ^ (rotate_left(x, 23))
            y = (rotate_left(W[j-13], 7)) ^ W[j-6]
            W.append(p1 ^ y)
        
        W1 = [W[j] ^ W[j+4] for j in range(64)]
        
        # 压缩函数
        A, B, C, D, E, F, G, H = V
        
        for j in range(64):
            SS1 = rotate_left(rotate_left(A, 12) + E + rotate_left(T[j], j % 32), 7)
            SS2 = SS1 ^ rotate_left(A, 12)
            TT1 = (ff(A, B, C, j) + D + SS2 + W1[j]) & 0xFFFFFFFF
            TT2 = (gg(E, F, G, j) + H + SS1 + W[j]) & 0xFFFFFFFF
            D = C
            C = rotate_left(B, 9)
            B = A
            A = TT1
            H = G
            G = rotate_left(F, 19)
            F = E
            E = p0(TT2)
        
        # 更新状态
        V = [(x ^ y) & 0xFFFFFFFF for x, y in zip(V, [A, B, C, D, E, F, G, H])]
    
    # 生成最终哈希值
    return ''.join(f"{x:08x}" for x in V)

def rotate_left(x, n):
    """循环左移"""
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

def ff(x, y, z, j):
    """布尔函数FF"""
    if j < 16:
        return x ^ y ^ z
    return (x & y) | (x & z) | (y & z)

def gg(x, y, z, j):
    """布尔函数GG"""
    if j < 16:
        return x ^ y ^ z
    return (x & y) | ((~x) & z)

def p0(x):
    """置换函数P0"""
    return x ^ rotate_left(x, 9) ^ rotate_left(x, 17)

def p1(x):
    """置换函数P1"""
    return x ^ rotate_left(x, 15) ^ rotate_left(x, 23)

# 基础版本的SM2算法实现
class BaseSM2:
    def __init__(self):
        # 椭圆曲线参数 (sm2p256v1)
        self.p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
        self.a = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
        self.b = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
        self.n = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
        self.Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
        self.Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
    
    def generate_keypair(self):
        """生成SM2密钥对"""
        d = random.randint(1, self.n-1)
        Px, Py = self.scalar_mult(d, self.Gx, self.Gy)
        return d, (Px, Py)
    
    def point_add(self, x1, y1, x2, y2):
        """椭圆曲线点加算法 - 基础版本"""
        p = self.p
        
        # 处理无穷远点
        if x1 is None and y1 is None:
            return x2, y2
        if x2 is None and y2 is None:
            return x1, y1
        
        # 相同点加倍
        if x1 == x2 and y1 == y2:
            # 计算斜率 s = (3x² + a)/(2y) mod p
            numerator = (3 * pow(x1, 2, p) + self.a) % p
            denominator = (2 * y1) % p
            inv_denom = pow(denominator, p-2, p)  # 费马小定理求逆
            s = (numerator * inv_denom) % p
        else:
            # 不同点相加
            numerator = (y2 - y1) % p
            denominator = (x2 - x1) % p
            inv_denom = pow(denominator, p-2, p)  # 费马小定理求逆
            s = (numerator * inv_denom) % p
        
        # 计算新点坐标
        x3 = (pow(s, 2, p) - x1 - x2) % p
        y3 = (s * (x1 - x3) - y1) % p
        
        return x3, y3
    
    def scalar_mult(self, k, x, y):
        """标量乘法 - 基础版本（简单累加）"""
        # 处理k=0的情况（无穷远点）
        if k == 0:
            return None, None
        
        # 初始化结果为无穷远点
        rx, ry = None, None
        current_x, current_y = x, y
        
        # 使用二进制展开
        while k:
            if k & 1:
                if rx is None:
                    rx, ry = current_x, current_y
                else:
                    rx, ry = self.point_add(rx, ry, current_x, current_y)
            
            # 点加倍
            current_x, current_y = self.point_add(current_x, current_y, current_x, current_y)
            k >>= 1
        
        return rx, ry
    
    def kdf(self, Z, klen):
        """密钥派生函数 (KDF) - 基础版本"""
        ct = 1
        ha = b''
        hash_len = 32  # SM3输出长度为32字节
        
        # 计算需要的哈希次数
        rounds = (klen + hash_len * 8 - 1) // (hash_len * 8)
        
        for i in range(rounds):
            # 构造输入数据: Z || ct
            data = Z + ct.to_bytes(4, 'big')
            # 计算SM3哈希
            hash_hex = sm3_hash(data)
            ha += bytes.fromhex(hash_hex)
            ct += 1
        
        # 转换为比特串并截取所需长度
        kbits = bin(int.from_bytes(ha, 'big'))[2:].zfill(len(ha) * 8)
        return kbits[:klen]
    
    def encrypt(self, pub_key, msg):
        """SM2加密算法 - 基础版本"""
        # 转换消息为字节
        if isinstance(msg, str):
            msg = msg.encode('utf-8')
        
        klen = len(msg) * 8  # 需要的密钥长度（比特）
        
        # 生成随机数k
        k = random.randint(1, self.n-1)
        
        # 计算C1 = k*G
        C1x, C1y = self.scalar_mult(k, self.Gx, self.Gy)
        C1 = (C1x, C1y)
        
        # 计算k*Pb = (x2, y2)
        x2, y2 = self.scalar_mult(k, pub_key[0], pub_key[1])
        
        # 将x2, y2转换为字节
        x2_bytes = x2.to_bytes(32, 'big')
        y2_bytes = y2.to_bytes(32, 'big')
        
        # 计算t = KDF(x2||y2, klen)
        t_bits = self.kdf(x2_bytes + y2_bytes, klen)
        
        # 检查t是否为全0
        if all(bit == '0' for bit in t_bits):
            return self.encrypt(pub_key, msg)  # 重新生成
        
        # 将消息转换为比特串
        msg_bits = bin(int.from_bytes(msg, 'big'))[2:].zfill(klen)
        
        # 计算C2 = M ⊕ t
        c2_bits = ''.join(str(int(a) ^ int(b)) for a, b in zip(msg_bits, t_bits))
        
        # 将C2转换回字节
        c2_int = int(c2_bits, 2)
        c2_bytes = c2_int.to_bytes((len(c2_bits) + 7) // 8, 'big')
        
        # 计算C3 = Hash(x2||M||y2)
        c3_data = x2_bytes + msg + y2_bytes
        C3 = sm3_hash(c3_data)
        
        # 格式化C1
        c1_bytes = b'\x04' + C1x.to_bytes(32, 'big') + C1y.to_bytes(32, 'big')
        
        return c1_bytes, c2_bytes, bytes.fromhex(C3)
    
    def decrypt(self, priv_key, cipher):
        """SM2解密算法 - 基础版本"""
        C1, C2, C3 = cipher
        
        # 从C1中提取点坐标
        if C1[0] != 0x04:
            raise ValueError("无效的点格式")
        
        C1x = int.from_bytes(C1[1:33], 'big')
        C1y = int.from_bytes(C1[33:65], 'big')
        
        # 验证点是否在曲线上
        left = pow(C1y, 2, self.p)
        right = (pow(C1x, 3, self.p) + self.a * C1x + self.b) % self.p
        if left != right:
            raise ValueError("点不在曲线上")
        
        # 计算d*C1 = (x2, y2)
        x2, y2 = self.scalar_mult(priv_key, C1x, C1y)
        
        # 将x2, y2转换为字节
        x2_bytes = x2.to_bytes(32, 'big')
        y2_bytes = y2.to_bytes(32, 'big')
        
        # 计算t = KDF(x2||y2, len(C2)*8)
        klen = len(C2) * 8
        t_bits = self.kdf(x2_bytes + y2_bytes, klen)
        
        # 检查t是否为全0
        if all(bit == '0' for bit in t_bits):
            raise ValueError("KDF产生全零密钥")
        
        # 将C2转换为比特串
        c2_bits = bin(int.from_bytes(C2, 'big'))[2:].zfill(klen)
        
        # 恢复明文 M = C2 ⊕ t
        msg_bits = ''.join(str(int(a) ^ int(b)) for a, b in zip(c2_bits, t_bits))
        
        # 将消息转换回字节
        msg_int = int(msg_bits, 2)
        msg = msg_int.to_bytes((len(msg_bits) + 7) // 8, 'big')
        
        # 验证C3 = Hash(x2||M||y2)
        c3_data = x2_bytes + msg + y2_bytes
        c3_calc = sm3_hash(c3_data)
        
        if c3_calc != C3.hex():
            raise ValueError("C3验证失败")
        
        return msg.decode('utf-8')

# 测试基础版本SM2
if __name__ == "__main__":
    sm2_base = BaseSM2()
    
    print("="*60)
    print("基础版本SM2算法测试")
    print("="*60)
    
    # 生成密钥对
    start_keygen = time.time()
    priv_key, pub_key = sm2_base.generate_keypair()
    keygen_time = time.time() - start_keygen
    print(f"私钥: {hex(priv_key)[:30]}...")
    print(f"公钥: ({hex(pub_key[0])[:30]}..., {hex(pub_key[1])[:30]}...)")
    print(f"密钥生成时间: {keygen_time:.6f}秒\n")
    
    # 加密消息
    msg = "SDUCST"
    start_encrypt = time.time()
    C1, C2, C3 = sm2_base.encrypt(pub_key, msg)
    encrypt_time = time.time() - start_encrypt
    print(f"C1 (点坐标): {C1.hex()[:30]}...")
    print(f"C2 (密文): {C2.hex()[:30]}...")
    print(f"C3 (哈希值): {C3.hex()[:30]}...")
    print(f"加密时间: {encrypt_time:.6f}秒\n")
    
    # 解密消息
    start_decrypt = time.time()
    decrypted_msg = sm2_base.decrypt(priv_key, (C1, C2, C3))
    decrypt_time = time.time() - start_decrypt
    print(f"解密结果: {decrypted_msg}")
    print(f"解密时间: {decrypt_time:.6f}秒")
    print("="*60)
