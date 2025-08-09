pragma circom 2.2.2;

// S-box Template: x^d (d=5)
template SBox() {
    signal input x;
    signal output out;
    
    signal x2;  // x^2
    signal x4;  // x^4
    signal x5;  // x^5
    
    x2 <== x * x;
    x4 <== x2 * x2;
    x5 <== x4 * x;
    out <== x5;
}

// Poseidon2 单轮逻辑
template Poseidon2Round(roundType, roundIdx, t_state_width) {
    signal input in_state[t_state_width];
    signal output out_state[t_state_width];
    
    // 硬编码MDS矩阵 (t=3)
    var MDS[3][3] = [
        [2, 1, 1],
        [1, 2, 1],
        [1, 1, 2]
    ];
    
    // 硬编码轮常数 (示例值，实际应使用标准参数)
    var roundConstants[64][3];
    for (var r = 0; r < 64; r++) {
        for (var i = 0; i < 3; i++) {
            roundConstants[r][i] = r * 3 + i + 1;
        }
    }
    
    // 1. 添加轮常数 (ARK)
    signal state_after_rc[t_state_width];
    for (var i = 0; i < t_state_width; i++) {
        state_after_rc[i] <== in_state[i] + roundConstants[roundIdx][i];
    }
    
    // 2. S-box应用
    signal state_after_sbox[t_state_width];
    
    if (roundType == 0) { // 完整S-box轮
        for (var i = 0; i < t_state_width; i++) {
            component sbox = SBox();
            sbox.x <== state_after_rc[i];
            state_after_sbox[i] <== sbox.out;
        }
    } else { // 部分S-box轮
        component sbox = SBox();
        sbox.x <== state_after_rc[0];
        state_after_sbox[0] <== sbox.out;
        
        for (var i = 1; i < t_state_width; i++) {
            state_after_sbox[i] <== state_after_rc[i];
        }
    }
    
    // 3. MDS矩阵乘法
    for (var i = 0; i < t_state_width; i++) {
        out_state[i] <== 
            MDS[i][0] * state_after_sbox[0] + 
            MDS[i][1] * state_after_sbox[1] + 
            MDS[i][2] * state_after_sbox[2];
    }
}

// Poseidon2 哈希主电路
template Poseidon2Hash() {
    // 算法参数 (t=3, 完整轮8, 部分轮56)
    var RF_FULL = 8;        // 完整轮数
    var RF_PARTIAL = 56;    // 部分轮数
    var TOTAL_ROUNDS = RF_FULL + RF_PARTIAL;
    var T_WIDTH = 3;        // 状态宽度
    
    // 输入信号
    signal input in_private[2];  // 两个256位隐私输入
    signal output hash;          // 256位哈希输出
    
    // 状态寄存器 [in1, in2, capacity]
    signal state[TOTAL_ROUNDS + 1][T_WIDTH];
    
    // 初始状态
    state[0][0] <== in_private[0];
    state[0][1] <== in_private[1];
    state[0][2] <== 0;  // 容量域
    
    // 轮组件实例化
    component rounds[TOTAL_ROUNDS];
    
    for (var r = 0; r < TOTAL_ROUNDS; r++) {
        // 确定轮类型: 首尾为完整轮，中间为部分轮
        var isFullRound = (r < RF_FULL / 2) || (r >= TOTAL_ROUNDS - RF_FULL / 2);
        var roundType = isFullRound ? 0 : 1;
        
        rounds[r] = Poseidon2Round(roundType, r, T_WIDTH);
        
        // 连接输入状态
        for (var i = 0; i < T_WIDTH; i++) {
            rounds[r].in_state[i] <== state[r][i];
        }
        
        // 连接输出状态
        for (var i = 0; i < T_WIDTH; i++) {
            state[r + 1][i] <== rounds[r].out_state[i];
        }
    }
    
    // 最终哈希输出为末状态的第一个元素
    hash <== state[TOTAL_ROUNDS][0];
}

// 主组件 - 指定公开信号为哈希值
component main {public [hash]} = Poseidon2Hash();
