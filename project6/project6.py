import hashlib
import random
from math import lcm

# 群参数
GROUP_P = 47       # 新的素数模数
GROUP_Q = 23       # 群的阶（素数，47-1=46=2×23）
GROUP_G = 5        # 新的生成元（满足5^23 ≡ 1 mod 47）

# Paillier参数
PAILLIER_P = 107   # 较大素数
PAILLIER_Q = 109   # 较大素数

def hash_to_group(u):
    """哈希函数：将标识符映射到群元素"""
    h_bytes = hashlib.sha3_256(u.encode()).digest()  # 改用SHA3-256
    h_int = int.from_bytes(h_bytes, 'little')        # 改为小端序
    exponent = h_int % GROUP_Q
    return pow(GROUP_G, exponent, GROUP_P)

class HomomorphicEncryption:
    def __init__(self, private_params=None, public_params=None):
        """重构初始化方式"""
        if private_params:  # 解密方
            p, q = private_params
            self.n = p * q
            self.lam = lcm(p-1, q-1)  # 使用lcm
            self.g = self.n + 1
            self.n_sq = self.n * self.n
            self.mu = pow(self.lam, -1, self.n)
        elif public_params:  # 加密方
            self.n, self.g = public_params
            self.n_sq = self.n * self.n
        else:
            raise ValueError("必须提供私钥参数或公钥参数")

    def encrypt_value(self, plaintext, rand=None):
        """加密方法"""
        if not 0 <= plaintext < self.n:
            raise ValueError(f"明文超出范围 [0, {self.n})")
        
        rand = rand or random.randrange(1, self.n)  # 使用randrange
        c = (pow(self.g, plaintext, self.n_sq) * pow(rand, self.n, self.n_sq)) % self.n_sq
        return c

    def decrypt_value(self, ciphertext):
        """解密方法"""
        if not hasattr(self, 'lam'):
            raise RuntimeError("缺少解密所需的私钥参数")
        
        c_lam = pow(ciphertext, self.lam, self.n_sq)
        l_val = (c_lam - 1) // self.n
        return (l_val * self.mu) % self.n

    def homomorphic_add(self, cipher1, cipher2):
        """同态加法"""
        return (cipher1 * cipher2) % self.n_sq
    
    def rerandomize(self, ciphertext):
        """密文随机化"""
        rand = random.randrange(1, self.n)
        rerandomizer = pow(rand, self.n, self.n_sq)
        return (ciphertext * rerandomizer) % self.n_sq

def execute_psi_protocol():
    """执行协议"""
    # 参与者输入数据
    party1_items = ["x", "y", "z", "w"]  # 修改元素标识
    party2_data = [("a", 15), ("y", 8), ("w", 12), ("b", 7)]  # 修改数据
    
    # 初始化阶段
    priv_key1 = random.randint(1, GROUP_Q-1)
    priv_key2 = random.randint(1, GROUP_Q-1)
    
    # P2生成加密密钥
    p2_crypto = HomomorphicEncryption(private_params=(PAILLIER_P, PAILLIER_Q))
    public_key = (p2_crypto.n, p2_crypto.g)
    print(f"同态加密公钥: n={public_key[0]}, g={public_key[1]}")

    # 第一轮通信：P1 → P2
    blinded_items = []
    for item in party1_items:
        h_val = hash_to_group(item)
        blinded = pow(h_val, priv_key1, GROUP_P)
        blinded_items.append(blinded)
    random.shuffle(blinded_items)

    # 第二轮通信：P2 → P1
    # 处理P1的盲化元素
    double_blinded = []
    for elem in blinded_items:
        db = pow(elem, priv_key2, GROUP_P)
        double_blinded.append(db)
    random.shuffle(double_blinded)
    
    # 处理P2的数据
    encrypted_pairs = []
    for identifier, value in party2_data:
        h_id = hash_to_group(identifier)
        h_id_k2 = pow(h_id, priv_key2, GROUP_P)
        enc_val = p2_crypto.encrypt_value(value)
        encrypted_pairs.append((h_id_k2, enc_val))
    random.shuffle(encrypted_pairs)

    # 第三轮通信：P1 → P2
    p1_crypto = HomomorphicEncryption(public_params=public_key)
    
    # 初始化为加密的零
    encrypted_sum = p1_crypto.encrypt_value(0)
    
    for h_k2, enc_val in encrypted_pairs:
        h_k1k2 = pow(h_k2, priv_key1, GROUP_P)
        if h_k1k2 in double_blinded:
            encrypted_sum = p1_crypto.homomorphic_add(encrypted_sum, enc_val)
    
    # 随机化最终结果
    randomized_sum = p1_crypto.rerandomize(encrypted_sum)

    # 结果解密
    sum_result = p2_crypto.decrypt_value(randomized_sum)
    
    # 验证结果
    intersection = [id for id in party1_items if id in [d[0] for d in party2_data]]
    actual_sum = sum(val for id, val in party2_data if id in party1_items)
    
    print("交集元素:", intersection)
    print("实际求和值:", actual_sum)
    print("协议计算结果:", sum_result)

if __name__ == "__main__":
    execute_psi_protocol()

