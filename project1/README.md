## SM4的软件实现与优化
### 引言
SM4.0（原名SMS4.0）是中华人民共和国政府采用的一种分组密码标准，由国家密码管理局于2012年3月21日发布。相关标准为“GM/T 0002-2012《SM4分组密码算法》（原SMS4分组密码算法）”。

在商用密码体系中，SM4主要用于数据加密，其算法公开，分组长度与密钥长度均为128bit，加密算法与密钥扩展算法都采用32轮非线性迭代结构，S盒为固定的8比特输入8比特输出。
### SM4算法流程
#### 密钥及密钥参量
SM4分组密码算法的加密密钥长度为128bit，表示为MK=(MK0,MK1,MK2,MK3)，其中MKi(i=0，1,2,3)为4bytes。

轮密钥表示为(rk0,rk1,···,rk31)，其中rki(i=0,1,···，31)为32bit。轮密钥由加密密钥生成。

FK=(FK1,FK2,FK3,FK4)为系统参数，CK=(CK0,CK1,···,CK31)为固定参数，用于密钥扩展算法，其中FKi(i=0,1,···，3)，CKi(i=0,1,···，31)均为32bit。
#### 加密算法
SM4加密算法由32次迭代运算和1次反序变换R组成

设明文输入为(X0,X1,X2,X3)，密文输出为(Y0,Y1,Y2,Y3),轮密钥为rki∈Z232，i=0,1,···，31。加密算法的运算过程如下。

（1）首先执行32次迭代运算：

Xi+4=F(Xi,Xi+1,Xi+2,Xi+3,rki)=Xi XOR T(Xi XOR Xi+1 XOR Xi+2 XOR Xi+3 XOR rki),i=0,1,···31

（2）对最后一轮数据进行反序变换并得到密文输出：

(Y0,Y1,Y2,Y3)=R(X32,X33,X34,X35)=(X35,X34,X33,X32)。

其中，T：Z232→Z232一个可逆变换，由非线性变换τ和线性变换L复合而成，即T(·)=L(τ(·))。

非线性变换τ由4个并行的S盒构成。设输入为A=(a0,a1,a2,a3)∈(Z28)4，非线性变换τ的输出为B=(b0,b1,b2,b3)∈(Z28)4，即：

(b0,b1,b2,b3)=τ(A)=(Sbox(a0),Sbox(a1),Sbox(a2),Sbox(a3))。

设S盒的输入为EF，则经S盒运算的输出结果结果为第E行、第F列的值，即Sbox(EF)=0x84。

L是线性变换，非线性变换τ的输出是线性变换L的输入。设输入为B∈Z232，则：

C=L(B)=B XOR (B<<<2) XOR (B<<<10) XOR (B<<<18) XOR (B<<<24)。
#### 解密算法
本算法的解密变换与加密变换结构相同，不同的仅是轮密钥的使用顺序，解密时使用轮密钥序(rk31,rk30,···,rk0)。
### 利用T-table优化SM4的原理
#### 优化原理
T-table优化的核心思想是通过预计算来减少加密过程中的计算量。SM4的轮函数包含两个主要操作：

非线性变换（S盒替换）、线性变换L（多个循环移位和异或）

这两个操作可以合并为一个查表操作，将原本需要多次计算的操作简化为一次内存访问。
#### 优势

将S盒查找和线性变换合并为单次查表操作

减少约75%的计算量（4字节并行处理）

避免复杂的位运算和移位操作

内存访问模式规律，缓存友好
### 利用AES-NI优化SM4的原理
#### 优化原理
AES-NI指令集包含专门为AES设计的硬件指令，但我们可以利用其中的AESENC指令来加速SM4的S盒操作。原理是：

SM4和AES的S盒都基于有限域逆运算

通过仿射变换将SM4 S盒转换为AES S盒格式

使用AESENC指令执行等效操作
#### 实现思路
```
#include <immintrin.h>

// 仿射变换矩阵（将SM4 S盒映射到AES S盒域）

  const __m128i AFFINE_FWD = _mm_set_epi64x(0x0C0A020803090E07, 0x01040F060D0B0500);

  const __m128i AFFINE_BWD = _mm_set_epi64x(0x070E090308020A0C, 0x00050B0D060F0401);

// 使用AES-NI加速S盒变换
__m128i sm4_sbox_aesni(__m128i x) {
    // 前向仿射变换
    x = _mm_gf2p8affine_epi64_epi8(x, AFFINE_FWD, 0);
    
    // 使用AESENC执行核心变换（等效于AES S盒）
    __m128i zero = _mm_setzero_si128();
    x = _mm_aesenc_si128(x, zero);
    
    // 反向仿射变换
    return _mm_gf2p8affine_epi64_epi8(x, AFFINE_BWD, 0);
}

// 向量化加密（4分组并行）
void sm4_encrypt_aesni(...) {
    __m128i state0, state1, state2, state3;
    // 加载4个分组
    
    for (int round = 0; round < 32; round++) {
        __m128i rk_vec = _mm_set1_epi32(rk[round]);
        __m128i tmp = _mm_xor_si128(state1, 
                           _mm_xor_si128(state2, 
                           _mm_xor_si128(state3, rk_vec)));
        
        // 使用AES-NI加速S盒
        tmp = sm4_sbox_aesni(tmp);
        
        // 应用线性变换L
        tmp = _mm_xor_si128(tmp, _mm_rol_epi32(tmp, 2));
        tmp = _mm_xor_si128(tmp, _mm_rol_epi32(tmp, 10));
        tmp = _mm_xor_si128(tmp, _mm_rol_epi32(tmp, 18));
        tmp = _mm_xor_si128(tmp, _mm_rol_epi32(tmp, 24));
        
        // 更新状态
        __m128i new_state = _mm_xor_si128(state0, tmp);
        state0 = state1;
        state1 = state2;
        state2 = state3;
        state3 = new_state;
    }
    // 存储结果
}
```
#### 优势
利用专用硬件指令，单周期完成S盒操作

支持128位向量化，同时处理4个分组

避免查表操作，减少内存访问

对旁路攻击更有抵抗力
### 利用GFNI优化SM4的原理
#### 优化原理
GFNI（Galois Field New Instructions）是Intel推出的专用指令集，可直接在硬件层面执行伽罗瓦域运算。SM4的S盒可分解为：

有限域GF(2⁸)上的逆运算、仿射变换

GFNI提供直接支持这两种操作的指令。
#### 实现思路
```
#include <immintrin.h>

// GFNI参数（仿射变换矩阵）
const __m128i GFNI_AFFINE = _mm_set_epi64x(0x1F3F5F7F1F3F5F7F, 0x0C0A020803090E07);
const __m128i GFNI_INV = _mm_set_epi64x(0x0E05060F0D080180, 0x040703090A0B0C02);

// 使用GFNI加速S盒
__m128i sm4_sbox_gfni(__m128i x) {
    // 有限域求逆
    x = _mm_gf2p8affineinv_epi64_epi8(x, GFNI_INV, 0);
    
    // 仿射变换
    return _mm_gf2p8affine_epi64_epi8(x, GFNI_AFFINE, 0);
}

// 完整轮函数优化
void sm4_encrypt_gfni(...) {
    // 与AES-NI类似，但使用GFNI指令
    for (...) {
        // ...
        tmp = sm4_sbox_gfni(tmp);
        
        // 使用VPROLD加速线性变换（AVX512）
        __m512i tmp512 = _mm512_broadcastd_epi32(tmp);
        __m512i ltmp = _mm512_xor_si512(
                   _mm512_xor_si512(
                   _mm512_xor_si512(
                   _mm512_rol_epi32(tmp512, 2),
                   _mm512_rol_epi32(tmp512, 10)),
                   _mm512_rol_epi32(tmp512, 18)),
                   _mm512_rol_epi32(tmp512, 24));
        // ...
    }
}
```
#### 优势
单条指令完成S盒核心操作

比AES-NI更高效（专用SM4指令）

支持512位向量化（AVX512），同时处理16个分组

与线性变换指令（VPROLD）完美配合

功耗更低，性能更高
### 实验结果
测试所用明文字符串为"SDUCST"：

具体结果参考图片project1-a
