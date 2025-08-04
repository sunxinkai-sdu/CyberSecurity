import math
import random
import time
from gmpy2 import invert, mpz

# SM3哈希算法实现
class SM3:
    def __init__(self):
        self.iv = "7380166F4914B2B9172442D7DA8A0600A96F30BC163138AAE38DEE4DB0FB0E4E"
        self.T = [0x79CC4519] * 16 + [0x7A879D8A] * 48
    
    @staticmethod
    def _left_rotate(x, n):
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF
    
    @staticmethod
    def _ff(x, y, z, j):
        if j < 16:
            return x ^ y ^ z
        return (x & y) | (x & z) | (y & z)
    
    @staticmethod
    def _gg(x, y, z, j):
        if j < 16:
            return x ^ y ^ z
        return (x & y) | (~x & z)
    
    @staticmethod
    def _p0(x):
        return x ^ SM3._left_rotate(x, 9) ^ SM3._left_rotate(x, 17)
    
    @staticmethod
    def _p1(x):
        return x ^ SM3._left_rotate(x, 15) ^ SM3._left_rotate(x, 23)
    
    def hash(self, msg):
        # 消息填充
        msg_hex = msg if isinstance(msg, str) else msg.hex()
        bit_length = len(msg_hex) * 4
        msg_hex += '8'
        while (len(msg_hex) * 4) % 512 != 448:
            msg_hex += '0'
        msg_hex += f"{bit_length:016X}"
        
        # 消息分组
        blocks = [msg_hex[i:i+128] for i in range(0, len(msg_hex), 128)]
        V = self.iv
        
        # 处理每个分组
        for block in blocks:
            # 消息扩展
            W = []
            for j in range(0, 16):
                W.append(int(block[j*8:j*8+8], 16))
            
            for j in range(16, 68):
                W.append(SM3._p1(W[j-16] ^ W[j-9] ^ SM3._left_rotate(W[j-3], 15)) ^ 
                         SM3._left_rotate(W[j-13], 7) ^ W[j-6])
            
            W1 = [W[j] ^ W[j+4] for j in range(64)]
            
            # 压缩函数
            A, B, C, D, E, F, G, H = [int(V[i*8:i*8+8], 16) for i in range(8)]
            
            for j in range(64):
                SS1 = SM3._left_rotate((SM3._left_rotate(A, 12) + E + SM3._left_rotate(self.T[j], j % 32)) & 0xFFFFFFFF, 7)
                SS2 = SS1 ^ SM3._left_rotate(A, 12)
                TT1 = (SM3._ff(A, B, C, j) + D + SS2 + W1[j]) & 0xFFFFFFFF
                TT2 = (SM3._gg(E, F, G, j) + H + SS1 + W[j]) & 0xFFFFFFFF
                D = C
                C = SM3._left_rotate(B, 9)
                B = A
                A = TT1
                H = G
                G = SM3._left_rotate(F, 19)
                F = E
                E = SM3._p0(TT2)
            
            # 更新状态
            V = ''.join(f"{(int(V[i*8:i*8+8], 16) ^ [A, B, C, D, E, F, G, H][i]) & 0xFFFFFFFF:08X}" 
                       for i in range(8))
        
        return V

# SM2椭圆曲线密码算法
class SM2:
    def __init__(self):
        # 椭圆曲线参数 (sm2p256v1)
        self.p = mpz(0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF)
        self.a = mpz(0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC)
        self.b = mpz(0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93)
        self.n = mpz(0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123)
        self.Gx = mpz(0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7)
        self.Gy = mpz(0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0)
        self.h = 1  # 余因子
        
        # 创建SM3实例
        self.sm3 = SM3()
    
    def generate_keypair(self):
        """生成SM2密钥对"""
        d = random.randint(1, self.n-1)
        Px, Py = self._scalar_mult(d, self.Gx, self.Gy)
        return d, (Px, Py)
    
    def _point_add(self, x1, y1, x2, y2):
        """椭圆曲线点加算法"""
        if x1 == x2 and y1 == (self.p - y2) % self.p:
            return None, None  # 无穷远点
        
        if x1 == x2 and y1 == y2:
            # 相同点加倍
            s = ((3 * x1*x1 + self.a) * invert(2 * y1, self.p)) % self.p
        else:
            # 不同点相加
            s = ((y2 - y1) * invert(x2 - x1, self.p)) % self.p
        
        x3 = (s*s - x1 - x2) % self.p
        y3 = (s*(x1 - x3) - y1) % self.p
        return x3, y3
    
    def _scalar_mult(self, k, x, y):
        """标量乘法 (使用双倍加法算法)"""
        k_bin = bin(k)[2:]
        rx, ry = x, y
        
        for i in range(1, len(k_bin)):
            # 点加倍
            rx, ry = self._point_add(rx, ry, rx, ry)
            if k_bin[i] == '1':
                rx, ry = self._point_add(rx, ry, x, y)
        return rx, ry
    
    def _kdf(self, Z, klen):
        """密钥派生函数 (KDF)"""
        ct = 0x00000001
        ha = b''
        for _ in range((klen + 255) // 256):
            data = Z + ct.to_bytes(4, 'big')
            hash_hex = self.sm3.hash(data.hex())
            ha += bytes.fromhex(hash_hex)
            ct += 1
        return ha[:klen//8]
    
    def encrypt(self, pub_key, msg):
        """SM2加密算法"""
        if isinstance(msg, str):
            msg = msg.encode('utf-8')
        
        klen = len(msg) * 8
        k = random.randint(1, self.n-1)
        
        # 计算C1 = k*G
        C1x, C1y = self._scalar_mult(k, self.Gx, self.Gy)
        C1 = bytes.fromhex(f"04{C1x:064x}{C1y:064x}")
        
        # 计算S = [h]Pb
        Sx, Sy = self._scalar_mult(self.h, pub_key[0], pub_key[1])
        if Sx is None:
            raise ValueError("Public key is at infinity")
        
        # 计算k*Pb = (x2, y2)
        x2, y2 = self._scalar_mult(k, pub_key[0], pub_key[1])
        x2_bytes = x2.to_bytes(32, 'big')
        y2_bytes = y2.to_bytes(32, 'big')
        
        # 计算t = KDF(x2||y2, klen)
        t = self._kdf(x2_bytes + y2_bytes, klen)
        if all(b == 0 for b in t):
            return self.encrypt(pub_key, msg)  # 重新生成
        
        # 计算C2 = M ⊕ t
        msg_int = int.from_bytes(msg, 'big')
        t_int = int.from_bytes(t, 'big')
        C2 = (msg_int ^ t_int).to_bytes(len(msg), 'big')
        
        # 计算C3 = Hash(x2||M||y2)
        C3_data = x2_bytes + msg + y2_bytes
        C3 = bytes.fromhex(self.sm3.hash(C3_data.hex()))
        
        return C1, C2, C3
    
    def decrypt(self, priv_key, cipher):
        """SM2解密算法"""
        C1, C2, C3 = cipher
        
        # 从C1中提取点
        if C1[0] != 0x04:
            raise ValueError("Invalid point format")
        C1x = int.from_bytes(C1[1:33], 'big')
        C1y = int.from_bytes(C1[33:65], 'big')
        
        # 验证C1是否在曲线上
        if not self._is_on_curve(C1x, C1y):
            raise ValueError("Point not on curve")
        
        # 计算S = [h]C1
        Sx, Sy = self._scalar_mult(self.h, C1x, C1y)
        if Sx is None:
            raise ValueError("Point at infinity")
        
        # 计算d*C1 = (x2, y2)
        x2, y2 = self._scalar_mult(priv_key, C1x, C1y)
        x2_bytes = x2.to_bytes(32, 'big')
        y2_bytes = y2.to_bytes(32, 'big')
        
        # 计算t = KDF(x2||y2, klen)
        klen = len(C2) * 8
        t = self._kdf(x2_bytes + y2_bytes, klen)
        if all(b == 0 for b in t):
            raise ValueError("KDF produced zero key")
        
        # 恢复明文 M = C2 ⊕ t
        C2_int = int.from_bytes(C2, 'big')
        t_int = int.from_bytes(t, 'big')
        msg = (C2_int ^ t_int).to_bytes(len(C2), 'big')
        
        # 验证C3 = Hash(x2||M||y2)
        C3_data = x2_bytes + msg + y2_bytes
        C3_calc = bytes.fromhex(self.sm3.hash(C3_data.hex()))
        if C3_calc != C3:
            raise ValueError("C3 verification failed")
        
        return msg.decode('utf-8')
    
    def _is_on_curve(self, x, y):
        """验证点是否在椭圆曲线上"""
        left = (y * y) % self.p
        right = (x*x*x + self.a*x + self.b) % self.p
        return left == right

# 测试代码
if __name__ == "__main__":
    sm2 = SM2()
    
    # 生成密钥对
    start = time.time()
    priv_key, pub_key = sm2.generate_keypair()
    keygen_time = time.time() - start
    print(f"私钥: {priv_key}\n公钥: ({pub_key[0]}, {pub_key[1]})")
    print(f"密钥生成时间: {keygen_time:.6f}秒\n")
    
    # 加密消息
    msg = "SDUCST"
    start = time.time()
    C1, C2, C3 = sm2.encrypt(pub_key, msg)
    encrypt_time = time.time() - start
    print(f"C1 (点坐标): {C1.hex()}")
    print(f"C2 (密文): {C2.hex()}")
    print(f"C3 (哈希值): {C3.hex()}")
    print(f"加密时间: {encrypt_time:.6f}秒\n")
    
    # 解密消息
    start = time.time()
    decrypted_msg = sm2.decrypt(priv_key, (C1, C2, C3))
    decrypt_time = time.time() - start
    print(f"解密结果: {decrypted_msg}")
    print(f"解密时间: {decrypt_time:.6f}秒\n")

