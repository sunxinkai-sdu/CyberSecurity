#include <iostream>
#include <vector>
#include <cstdint>
#include <iomanip>
#include <string>
#include <sstream>
#include <ctime>
#include <immintrin.h>

using namespace std;

// 循环左移
inline uint32_t ROL(uint32_t x, uint32_t n) {
    return (x << (n & 0x1F)) | (x >> ((32 - n) & 0x1F));
}

// 布尔函数宏定义
#define FF0(X, Y, Z) ((X) ^ (Y) ^ (Z))
#define FF1(X, Y, Z) (((X) & (Y)) | ((X) & (Z)) | ((Y) & (Z)))
#define GG0(X, Y, Z) ((X) ^ (Y) ^ (Z))
#define GG1(X, Y, Z) (((X) & (Y)) | ((~(X)) & (Z)))

// 置换函数宏定义
#define P0(X) ((X) ^ ROL(X, 9) ^ ROL(X, 17))
#define P1(X) ((X) ^ ROL(X, 15) ^ ROL(X, 23))

// 预计算常量表
constexpr uint32_t T0[16] = {
    0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519,
    0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519,
    0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519,
    0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519
};

constexpr uint32_t T1[48] = {
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A
};

class SM3 {
public:
    SM3() { reset(); }

    void reset() {
        state[0] = 0x7380166F;
        state[1] = 0x4914B2B9;
        state[2] = 0x172442D7;
        state[3] = 0xDA8A0600;
        state[4] = 0xA96F30BC;
        state[5] = 0x163138AA;
        state[6] = 0xE38DEE4D;
        state[7] = 0xB0FB0E4E;
        total_len = 0;
        buffer.clear();
        buffer.reserve(64);
    }

    // 设置内部状态（用于长度扩展攻击）
    void set_state(const uint32_t new_state[8], uint64_t new_total_len) {
        for (int i = 0; i < 8; i++) {
            state[i] = new_state[i];
        }
        total_len = new_total_len;
        buffer.clear();
    }

    void update(const uint8_t* data, size_t len) {
        total_len += len;
        size_t offset = 0;

        // 处理缓冲区中已有数据
        if (!buffer.empty()) {
            size_t fill = min(64 - buffer.size(), len);
            buffer.insert(buffer.end(), data, data + fill);
            offset += fill;

            if (buffer.size() == 64) {
                process_block(buffer.data());
                buffer.clear();
            }
        }

        // 处理完整块
        while (offset + 64 <= len) {
            process_block(data + offset);
            offset += 64;
        }

        // 保存剩余数据
        if (offset < len) {
            buffer.insert(buffer.end(), data + offset, data + len);
        }
    }

    void finalize() {
        uint64_t bit_len = total_len * 8;

        // 添加填充
        buffer.push_back(0x80);
        size_t len_mod = buffer.size() % 64;
        size_t padding_len = (len_mod <= 56) ? (56 - len_mod) : (120 - len_mod);
        buffer.insert(buffer.end(), padding_len, 0);

        // 添加长度
        for (int i = 7; i >= 0; --i) {
            buffer.push_back(static_cast<uint8_t>((bit_len >> (i * 8)) & 0xFF));
        }

        // 处理填充块
        for (size_t i = 0; i < buffer.size(); i += 64) {
            process_block(buffer.data() + i);
        }
        buffer.clear();
    }

    string digest() {
        stringstream ss;
        ss << hex << setfill('0');
        for (int i = 0; i < 8; ++i) {
            ss << setw(8) << state[i];
        }
        return ss.str();
    }

    // 获取当前状态（用于长度扩展攻击）
    void get_state(uint32_t out_state[8]) const {
        for (int i = 0; i < 8; i++) {
            out_state[i] = state[i];
        }
    }

    // 获取当前总长度
    uint64_t get_total_len() const {
        return total_len;
    }

    // 直接获取状态而不进行填充（用于长度扩展攻击）
    string digest_without_finalize() {
        stringstream ss;
        ss << hex << setfill('0');
        for (int i = 0; i < 8; ++i) {
            ss << setw(8) << state[i];
        }
        return ss.str();
    }

private:
    // 块处理
    void process_block(const uint8_t* block) {
        uint32_t W[68];
        uint32_t W1[64];

        // 加载前16个字
        for (int i = 0; i < 16; ++i) {
            W[i] = (static_cast<uint32_t>(block[i * 4]) << 24) |
                (static_cast<uint32_t>(block[i * 4 + 1]) << 16) |
                (static_cast<uint32_t>(block[i * 4 + 2]) << 8) |
                static_cast<uint32_t>(block[i * 4 + 3]);
        }

        // 消息扩展
        for (int j = 16; j < 68; j += 4) {
            W[j] = P1(W[j - 16] ^ W[j - 9] ^ ROL(W[j - 3], 15)) ^ ROL(W[j - 13], 7) ^ W[j - 6];
            W[j + 1] = P1(W[j - 15] ^ W[j - 8] ^ ROL(W[j - 2], 15)) ^ ROL(W[j - 12], 7) ^ W[j - 5];
            W[j + 2] = P1(W[j - 14] ^ W[j - 7] ^ ROL(W[j - 1], 15)) ^ ROL(W[j - 11], 7) ^ W[j - 4];
            W[j + 3] = P1(W[j - 13] ^ W[j - 6] ^ ROL(W[j], 15)) ^ ROL(W[j - 10], 7) ^ W[j - 3];
        }

        // 计算W'
        for (int j = 0; j < 64; j += 4) {
            W1[j] = W[j] ^ W[j + 4];
            W1[j + 1] = W[j + 1] ^ W[j + 5];
            W1[j + 2] = W[j + 2] ^ W[j + 6];
            W1[j + 3] = W[j + 3] ^ W[j + 7];
        }

        // 寄存器变量
        uint32_t A = state[0];
        uint32_t B = state[1];
        uint32_t C = state[2];
        uint32_t D = state[3];
        uint32_t E = state[4];
        uint32_t F = state[5];
        uint32_t G = state[6];
        uint32_t H = state[7];

        // 前16轮
        for (int j = 0; j < 16; ++j) {
            uint32_t A_rot12 = ROL(A, 12);
            uint32_t T_rot = ROL(T0[j], j);
            uint32_t SS1 = ROL(A_rot12 + E + T_rot, 7);
            uint32_t SS2 = SS1 ^ A_rot12;

            uint32_t TT1 = FF0(A, B, C) + D + SS2 + W1[j];
            uint32_t TT2 = GG0(E, F, G) + H + SS1 + W[j];

            D = C;
            C = ROL(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = ROL(F, 19);
            F = E;
            E = P0(TT2);
        }

        // 后48轮
        for (int j = 16; j < 64; ++j) {
            uint32_t A_rot12 = ROL(A, 12);
            uint32_t T_rot = ROL(T1[j - 16], j);
            uint32_t SS1 = ROL(A_rot12 + E + T_rot, 7);
            uint32_t SS2 = SS1 ^ A_rot12;

            uint32_t TT1 = FF1(A, B, C) + D + SS2 + W1[j];
            uint32_t TT2 = GG1(E, F, G) + H + SS1 + W[j];

            D = C;
            C = ROL(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = ROL(F, 19);
            F = E;
            E = P0(TT2);
        }

        // 更新状态
        state[0] ^= A;
        state[1] ^= B;
        state[2] ^= C;
        state[3] ^= D;
        state[4] ^= E;
        state[5] ^= F;
        state[6] ^= G;
        state[7] ^= H;
    }

    uint32_t state[8];
    uint64_t total_len;
    vector<uint8_t> buffer;
};

string sm3_hash(const string& input) {
    SM3 sm3;
    sm3.update(reinterpret_cast<const uint8_t*>(input.data()), input.size());
    sm3.finalize();
    return sm3.digest();
}

// 长度扩展攻击演示
void length_extension_attack() {
    cout << "\n==================== 长度扩展攻击演示 ====================\n";

    // 原始消息
    string secret = "This is a secret message";
    string suffix = "&admin=true";

    // 计算原始消息的哈希值
    string original_hash = sm3_hash(secret);
    cout << "原始消息: \"" << secret << "\"\n";
    cout << "原始哈希: " << original_hash << "\n\n";

    // 攻击者不知道原始消息内容，但知道其哈希值和长度
    size_t secret_length = secret.length();

    // 计算填充长度
    size_t pad_len = (secret_length % 64 < 56) ?
        (56 - secret_length % 64) :
        (120 - secret_length % 64);

    // 计算填充后的总长度（位）
    uint64_t bit_length = secret_length * 8;
    // 计算填充后的总长度（字节）
    size_t padded_length = secret_length + 1 + pad_len + 8;

    // 从原始哈希值恢复内部状态
    SM3 sm3_attack;
    uint32_t state[8];
    // 将哈希字符串转换为状态数组
    for (int i = 0; i < 8; i++) {
        string hex_word = original_hash.substr(i * 8, 8);
        state[i] = stoul(hex_word, nullptr, 16);
    }

    // 设置恢复的状态和总长度（原始消息+填充）
    sm3_attack.set_state(state, padded_length);

    // 更新后缀（关键：不调用finalize）
    sm3_attack.update(reinterpret_cast<const uint8_t*>(suffix.data()), suffix.size());

    // 直接获取状态而不进行填充
    string forged_hash = sm3_attack.digest_without_finalize();

    // 计算真实扩展消息的哈希值（用于验证）
    string full_message = secret;
    // 添加填充
    full_message.push_back(0x80);
    full_message.append(pad_len, 0);
    // 添加长度（大端序）
    for (int i = 7; i >= 0; i--) {
        full_message.push_back(static_cast<uint8_t>((bit_length >> (i * 8)) & 0xFF));
    }
    full_message += suffix;

    // 计算完整消息的哈希值（同样不进行填充）
    SM3 sm3_real;
    sm3_real.update(reinterpret_cast<const uint8_t*>(full_message.data()), full_message.size());
    string real_hash = sm3_real.digest_without_finalize();

    // 输出结果
    cout << "攻击者构造的伪造消息: [原始消息的填充] + \"" << suffix << "\"\n";
    cout << "伪造消息的哈希: " << forged_hash << "\n";
    cout << "真实扩展消息的哈希: " << real_hash << "\n";

    if (forged_hash == real_hash) {
        cout << "\n>>> 攻击成功！伪造哈希与真实哈希匹配 <<<\n";
    }
    else {
        cout << "\n>>> 攻击失败！哈希值不匹配 <<<\n";
    }

    cout << "=======================================================\n";
}

// 性能测试
int main() {
    // 正确性测试
    cout << "SM3哈希算法实现\n";
    cout << "==================== 正确性测试 ====================\n";
    cout << "SM3(\"abc\") = " << sm3_hash("abc") << endl;
    cout << "标准值: 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0\n\n";

    cout << "SM3(\"abcdabcdabcdabcdabcdabcdabcd\") = "
        << sm3_hash("abcdabcdabcdabcdabcdabcdabcd") << endl;
    cout << "标准值: debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732\n\n";

    // 性能测试
    cout << "==================== 性能测试 ====================\n";
    string long_str(1024 * 1024, 'a'); // 1MB数据
    const int iterations = 100; // 多次迭代获取准确时间

    clock_t start = clock();
    for (int i = 0; i < iterations; ++i) {
        SM3 sm3;
        sm3.update(reinterpret_cast<const uint8_t*>(long_str.data()), long_str.size());
        sm3.finalize();
        sm3.digest();
    }
    clock_t end = clock();

    double total_time = (double)(end - start) / CLOCKS_PER_SEC;
    double avg_time = total_time / iterations * 1000; // 单次平均时间(ms)
    double speed = (long_str.size() * iterations / 1024.0 / 1024.0) / total_time; // MB/s

    cout << "数据大小: 1 MB\n";
    cout << "迭代次数: " << iterations << "\n";
    cout << "总时间: " << fixed << setprecision(3) << total_time * 1000 << " ms\n";
    cout << "平均时间: " << fixed << setprecision(3) << avg_time << " ms\n";
    cout << "吞吐量: " << fixed << setprecision(2) << speed << " MB/s\n\n";

    // 执行长度扩展攻击演示
    length_extension_attack();

    return 0;
}
