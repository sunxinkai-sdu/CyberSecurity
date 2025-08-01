#include <cstdint>
#include <cstring>
#include <iostream>
#include <iomanip>
#include <vector>
#include <random>
#include <windows.h>

using namespace std;

// SM4常量定义
static const uint8_t Sbox[256] = {
    0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
    0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
    0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
    0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
    0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
    0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
    0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
    0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
    0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
    0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
    0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
    0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
    0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
    0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
    0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
    0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48
};

static const uint8_t MK[16] = {
    0x01,0x23,0x45,0x67, 0x89,0xab,0xcd,0xef,
    0xfe,0xdc,0xba,0x98, 0x76,0x54,0x32,0x10
};

static const uint32_t FK[4] = {
    0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc
};

static const uint32_t CK[32] = {
    0x00070e15,0x1c232a31,0x383f464d,0x545b6269,
    0x70777e85,0x8c939aa1,0xa8afb6bd,0xc4cbd2d9,
    0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249,
    0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,
    0xc0c7ced5,0xdce3eaf1,0xf8ff060d,0x141b2229,
    0x30373e45,0x4c535a61,0x686f767d,0x848b9299,
    0xa0a7aeb5,0xbcc3cad1,0xd8dfe6ed,0xf4fb0209,
    0x10171e25,0x2c333a41,0x484f565d,0x646b7279
};

// 优化后的T-table实现
static uint32_t T_table[4][256]; // 四个独立的T-table

// 循环左移
static inline uint32_t rotate_left(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

// 线性变换L
static inline uint32_t linear_transform(uint32_t x) {
    return x ^ rotate_left(x, 2) ^ rotate_left(x, 10) ^ rotate_left(x, 18) ^ rotate_left(x, 24);
}

// 初始化T-table
void init_T_table() {
    for (int i = 0; i < 256; i++) {
        uint32_t s = Sbox[i];
        // 为每个字节位置创建独立的T-table
        T_table[0][i] = linear_transform(s << 24);
        T_table[1][i] = linear_transform(s << 16);
        T_table[2][i] = linear_transform(s << 8);
        T_table[3][i] = linear_transform(s);
    }
}

// 非线性变换τ (Tau)
static inline uint32_t tau(uint32_t x) {
    return (Sbox[(x >> 24) & 0xFF] << 24) |
        (Sbox[(x >> 16) & 0xFF] << 16) |
        (Sbox[(x >> 8) & 0xFF] << 8) |
        Sbox[x & 0xFF];
}

// 密钥扩展
void key_expansion(const uint8_t key[16], uint32_t rk[32]) {
    uint32_t K[36];

    // 加载初始密钥
    for (int i = 0; i < 4; i++) {
        K[i] = ((uint32_t)key[4 * i] << 24) |
            ((uint32_t)key[4 * i + 1] << 16) |
            ((uint32_t)key[4 * i + 2] << 8) |
            key[4 * i + 3];
        K[i] ^= FK[i];  // 应用FK常量
    }

    // 生成轮密钥
    for (int i = 0; i < 32; i++) {
        uint32_t tmp = K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ CK[i];
        uint32_t B = tau(tmp);  // 非线性变换
        rk[i] = K[i] ^ B ^ rotate_left(B, 13) ^ rotate_left(B, 23);
        K[i + 4] = rk[i];
    }
}

// 使用T-table优化的加密函数
void sm4_encrypt(const uint8_t in[16], uint8_t out[16], const uint32_t rk[32]) {
    uint32_t state[36];

    // 加载输入数据
    for (int i = 0; i < 4; i++) {
        state[i] = ((uint32_t)in[4 * i] << 24) |
            ((uint32_t)in[4 * i + 1] << 16) |
            ((uint32_t)in[4 * i + 2] << 8) |
            in[4 * i + 3];
    }

    // 32轮加密（使用T-table优化）
    for (int round = 0; round < 32; round++) {
        uint32_t tmp = state[round + 1] ^ state[round + 2] ^ state[round + 3] ^ rk[round];

        // 使用T-table加速轮函数
        state[round + 4] = state[round] ^
            T_table[0][(tmp >> 24) & 0xFF] ^
            T_table[1][(tmp >> 16) & 0xFF] ^
            T_table[2][(tmp >> 8) & 0xFF] ^
            T_table[3][tmp & 0xFF];
    }

    // 反转并存储结果
    for (int i = 0; i < 4; i++) {
        uint32_t val = state[35 - i];
        out[4 * i] = (val >> 24) & 0xFF;
        out[4 * i + 1] = (val >> 16) & 0xFF;
        out[4 * i + 2] = (val >> 8) & 0xFF;
        out[4 * i + 3] = val & 0xFF;
    }
}

// CBC模式加密
void cbc_encrypt(const vector<uint8_t>& plaintext, vector<uint8_t>& ciphertext,
    const uint32_t rk[32], const uint8_t iv[16]) {
    size_t block_count = plaintext.size() / 16;
    ciphertext.resize(plaintext.size());

    uint8_t prev_block[16];
    memcpy(prev_block, iv, 16);

    for (size_t i = 0; i < block_count; i++) {
        uint8_t block[16];

        // CBC异或操作
        for (int j = 0; j < 16; j++) {
            block[j] = plaintext[i * 16 + j] ^ prev_block[j];
        }

        // SM4加密
        sm4_encrypt(block, &ciphertext[i * 16], rk);

        // 更新前一个密文块
        memcpy(prev_block, &ciphertext[i * 16], 16);
    }
}

int main() {
    // 初始化T-table
    init_T_table();

    // 生成轮密钥
    uint32_t rk[32];
    key_expansion(MK, rk);

    // 生成随机IV
    uint8_t iv[16];
    random_device rd;
    for (int i = 0; i < 16; i++) {
        iv[i] = static_cast<uint8_t>(rd());
    }

    // 准备明文（PKCS#7填充）
    string plaintext = "SDUCST";
    size_t orig_len = plaintext.length();
    size_t padded_len = (orig_len + 15) & ~15;  // 16字节对齐
    vector<uint8_t> padded_plaintext(padded_len);
    memcpy(padded_plaintext.data(), plaintext.data(), orig_len);

    // 填充字节
    uint8_t pad_value = static_cast<uint8_t>(padded_len - orig_len);
    for (size_t i = orig_len; i < padded_len; i++) {
        padded_plaintext[i] = pad_value;
    }

    // 加密
    vector<uint8_t> ciphertext;

    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);

    // CBC模式加密
    cbc_encrypt(padded_plaintext, ciphertext, rk, iv);

    QueryPerformanceCounter(&end);
    double elapsed = (end.QuadPart - start.QuadPart) * 1000.0 / freq.QuadPart;

    // 输出结果
    cout << "IV: ";
    for (int i = 0; i < 16; i++) {
        cout << hex << setw(2) << setfill('0') << static_cast<int>(iv[i]);
    }
    cout << "\nCiphertext: ";
    for (auto b : ciphertext) {
        cout << hex << setw(2) << setfill('0') << static_cast<int>(b);
    }
    cout << "\nEncryption time: " << fixed << setprecision(3) << elapsed << " ms\n";

    return 0;
}