## 用circom实现poseidon2哈希算法的电路
(1) poseidon2哈希算法参数参考参考文档1的Table1，用(n,t,d)=(256,3,5)或(256,2,5)

(2)电路的公开输入用poseidon2哈希值，隐私输入为哈希原象，哈希算法的输入只考虑一个block即可。

(3) 用Groth16算法生成证明
### 实现思路
#### Poseidon2算法
* 基于海绵结构，使用置换函数处理输入

#### 电路设计

* 隐私输入：两个256位字段元素（原象）

* 公开输入：哈希结果（256位）

* 使用参数(n,t,d) = (256,3,5)（状态大小3，S-box指数5）

#### 置换过程

* ARK：添加轮常数

* S-box：非线性变换（x⁵）

* MDS：线性扩散层

#### Groth16
* 使用Circom的Groth16模板生成证明

### 实现说明
#### 算法参数

* 状态宽度 t = 3（两个输入 + 1个容量）

* 完整轮数 RF_FULL = 8（首尾各4轮）

* 部分轮数 RF_PARTIAL = 56（中间部分）

* 总轮数 64（8+56）

#### 核心组件：

##### SBox
实现非线性变换 $x^5$

##### Poseidon2Round
* 单轮处理逻辑
  
* 根据轮类型应用完整/部分S-box
  
* 使用硬编码的MDS矩阵和轮常数

##### Poseidon2Hash
* 主哈希电路

* 初始化状态 [in1, in2, 0]

* 连接64轮处理组件

* 输出最终状态的第一个元素作为哈希值

##### Groth16集成

* 公开信号：hash（哈希输出）

* 隐私信号：in_private[2]（两个输入字段）

* 使用 === 约束确保公开信号正确性

### 编译和证明生成
#### 安装依赖
```
npm install circom circomlib snarkjs
```
#### 创建测试脚本
```
const { wasm: wasmTester } = require("circom_tester");
const { groth16 } = require("snarkjs");
const { poseidon } = require("circomlibjs");

async function main() {
    // 1. 编译电路
    const circuit = await wasmTester("poseidon2.circom");
    
    // 2. 准备输入数据
    const inputs = {
        in_private: [
            "12345678901234567890123456789012",  // 输入1
            "98765432109876543210987654321098"   // 输入2
        ]
    };
    
    // 3. 计算预期哈希值 (使用JavaScript实现作为参考)
    const hash = await poseidon(inputs.in_private);
    inputs.hash = hash.toString();
    
    // 4. 生成见证
    const witness = await circuit.calculateWitness(inputs);
    
    // 5. Groth16设置
    const zkey = await groth16.setup(circuit);
    
    // 6. 生成证明
    const { proof, publicSignals } = await groth16.prove(zkey, witness);
    
    console.log("Proof:", proof);
    console.log("Public Signals:", publicSignals);
    
    // 7. 验证证明
    const verificationKey = await groth16.exportVerificationKey(zkey);
    const isValid = await groth16.verify(verificationKey, publicSignals, proof);
    console.log("Verification:", isValid ? "SUCCESS" : "FAILED");
}

main().catch(console.error);
```
### Groth16 在 Circom 中的实现流程
```
graph TD
    A[编写 Circom 电路] --> B[编译电路]
    B --> C[生成 R1CS 和 WASM]
    C --> D[可信设置]
    D --> E[生成证明密钥 pk 和验证密钥 vk]
    E --> F[计算见证 Witness]
    F --> G[生成证明 Proof]
    G --> H[验证证明]
```
