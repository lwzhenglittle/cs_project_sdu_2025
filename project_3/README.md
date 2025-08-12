# 项目3：Poseidon2 零知识哈希函数实现

本项目使用JavaScript和Circom实现了Poseidon2哈希函数。

## 项目概述

### 核心特性

- **域原生运算**：在大素数域上执行算术运算
- **零知识友好**：专为高效约束表示而设计
- **安全性保证**：基于包含完整轮和部分轮的Hades置换
- **参数灵活**：支持不同的域大小和输入长度

## 实现参数

### 使用参数
- **有限域**：BN254标量域 (21888242871839275222246405745257275088548364400416034343698204186575808495617)
- **状态宽度**：3个元素
- **完整轮数**：8轮（开始4轮，结束4轮）
- **部分轮数**：56轮
- **S盒**：x^5

本项目根据论文规范[eprint.iacr.org/2023/323.pdf](https://eprint.iacr.org/2023/323.pdf)实现Poseidon2哈希算法。实现采用参数集合`(n, t, d) = (256, 3, 5)`，其中：

- **n = 256**：安全级别（比特）
- **t = 3**：状态大小（域元素数量）
- **d = 5**：S盒指数

## 电路设计

- **公开输入**：Poseidon2哈希输出（摘要）
- **私有输入**：原像（2个域元素的消息块）
- **约束条件**：电路验证 `Poseidon2(原像) == 摘要`

## 文件结构

```
project_3/
├── poseidon2.circom
├── constants.js
├── input.json
├── compute_hash.js
├── compile.sh
├── setup.sh
├── prove.sh
├── verify.sh
└── README.md
```

## 环境要求

安装所需工具：

```bash
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs
git clone https://github.com/iden3/circom.git
cd circom
cargo build --release
cargo install --path circom
cd ..
npm install -g snarkjs
```

## 使用说明

按顺序执行以下步骤来编译电路并生成证明：

### 步骤1：编译电路

```bash
./compile.sh
```

此操作将：
- 将`poseidon2.circom`编译为R1CS约束系统
- 生成用于见证计算的WebAssembly文件
- 创建用于调试的符号表

预期输出文件：
- `build/poseidon2.r1cs`
- `build/poseidon2_js/poseidon2.wasm`
- `build/poseidon2.sym`

### 步骤2：执行可信设置

```bash
./setup.sh
```

执行Groth16可信设置流程：
- 生成tau的幂次
- 创建证明密钥和验证密钥
- 导出验证密钥

预期输出文件：
- `keys/poseidon2.zkey`
- `keys/verification_key.json`

### 步骤3：生成证明

```bash
./prove.sh
```

此操作将：
- 从input.json计算见证
- 使用Groth16生成零知识证明
- 输出证明和公开输入

预期输出文件：
- `proofs/witness.wtns`
- `proofs/proof.json`
- `proofs/public.json`

### 步骤4：验证证明

```bash
./verify.sh
```

验证生成的证明并确认其有效性。

## 示例输入

`input.json`文件包含：

```json
{
  "preimage": ["123456789", "987654321"],
  "digest": "computed_hash_value"
}
```

对于新输入，可使用以下命令计算正确的哈希值：

```bash
node compute_hash.js
```

## 算法详述

### Poseidon2参数

- **有限域**：BN128标量域 (p = 21888242871839275222246405745257275088548364400416034343698204186575808495617)
- **完整轮数**：R_F = 8（开始4轮 + 结束4轮）
- **部分轮数**：R_P = 56（中间部分）
- **S盒**：素数域上的x^5
- **MDS矩阵**：优化的3×3 Cauchy矩阵

### 轮函数结构

1. 初始状态：将原像加载到前2个位置，用0填充第3个位置
2. 前4个完整轮：加常数 → S盒变换（全部） → 混合层
3. 56个部分轮：加常数 → S盒变换（仅第一个元素） → 混合层
4. 后4个完整轮：加常数 → S盒变换（全部） → 混合层
5. 输出：最终状态的第一个元素

### 安全性分析

本电路提供：
- 原像抗性：给定哈希值，难以找到原像
- 零知识性：证明不泄露原像的任何信息
- 可靠性：无效证明以高概率被拒绝

## 参考

1. [Poseidon2论文](https://eprint.iacr.org/2023/323.pdf)
2. [Circom文档](https://docs.circom.io/)
3. [Circomlib](https://github.com/iden3/circomlib)
4. [snarkjs](https://github.com/iden3/snarkjs)
