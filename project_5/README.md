# SM2 公钥密码算法实现

基于 GM/T 0003.5-2012 标准的完整 Python SM2 公钥密码算法实现。

## 概述

本实现提供完整的 SM2 密码系统功能：
- **密钥对生成** - 使用密码学安全随机数
- **数字签名生成与验证**
- **公钥加密与解密**
- **SM3 哈希函数** 实现 (GM/T 0004-2012)
- **十六进制字符串输入输出** - 兼容性支持
- **完整椭圆曲线运算** - 素数域上的运算

## 文件结构

```
project_5/
├── sm2.py              # SM2 主实现（签名、加密功能）
├── sm2_math.py         # 椭圆曲线数学运算和域运算
├── sm3.py              # SM3 哈希函数实现
├── utils.py            # 十六进制转换工具函数
├── test_sm2.py         # 完整单元测试和测试向量
├── demo.py             # 使用演示脚本
└── README.md           # 本文件
```

## 快速开始

### 密钥生成

```python
from sm2 import generate_key_pair

# 生成新的 SM2 密钥对
keypair = generate_key_pair()
print(f"私钥: {keypair.private_key_hex}")
print(f"公钥: {keypair.public_key_hex}")
```

### 数字签名

```python
from sm2 import sign_message, verify_signature, sign_text, verify_text

# 对十六进制消息签名
message_hex = "48656C6C6F20534D32"  # "Hello SM2"
signature = sign_message(message_hex, keypair.private_key_hex)
is_valid = verify_signature(message_hex, signature, keypair.public_key_hex)

# 直接对文本签名
text = "Hello SM2"
signature = sign_text(text, keypair.private_key_hex)
is_valid = verify_text(text, signature, keypair.public_key_hex)
```

### 公钥加密

```python
from sm2 import encrypt_message, decrypt_message, encrypt_text, decrypt_text

# 加密十六进制数据
message_hex = "48656C6C6F20534D32"
ciphertext = encrypt_message(message_hex, keypair.public_key_hex)
plaintext = decrypt_message(ciphertext, keypair.private_key_hex)

# 直接加密文本
text = "Secret message"
ciphertext = encrypt_text(text, keypair.public_key_hex)
plaintext = decrypt_text(ciphertext, keypair.private_key_hex)
```

## 运行测试

```bash
# 运行所有单元测试
python test_sm2.py

# 运行 SM3 哈希函数测试
python sm3.py

# 运行演示程序
python demo.py
```

## 实现细节

### 椭圆曲线参数

实现使用推荐的 SM2 椭圆曲线（素数域 Fp）：
- **素数**: p = 2^256 - 2^224 - 2^96 + 2^64 - 1
- **曲线方程**: y² = x³ + ax + b (mod p)
- **曲线参数 a**: FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
- **曲线参数 b**: 28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
- **基点阶数**: n = FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123

### 安全特性

- **密码学安全随机数生成** - 使用 Python `secrets` 模块
- **时间安全比较** - 防止时间攻击
- **完整参数验证** - 对所有输入进行验证
- **完整错误处理** - 提供详细错误信息
- **无第三方密码学依赖** - 纯 Python 实现

### 密钥格式

- **私钥**: 64 个十六进制字符（256 位）
- **公钥**: 128 个十六进制字符（512 位，非压缩格式：x || y）
- **签名**: 128 个十六进制字符（512 位：r || s）
- **所有输入输出**: 十六进制字符串，最大兼容性

## 性能表现

实现优先考虑正确性和安全性而非速度。现代硬件上的典型性能：

- **密钥生成**: ~0.05-0.1 秒/密钥对
- **签名生成**: ~0.02-0.05 秒/签名
- **签名验证**: ~0.03-0.06 秒/验证
- **加密**: ~0.05-0.1 秒（取决于消息大小）

## 测试向量

实现通过各种测试向量验证：
- 已知私钥/公钥对测试
- 签名生成和验证测试
- 加密/解密往返测试
- 边界条件和错误情况测试
- 不同实现间的交叉兼容性测试

## 使用示例

### 基本使用

```python
# 密钥生成
keypair = generate_key_pair()

# 数字签名
signature = sign_text("消息内容", keypair.private_key_hex)
is_valid = verify_text("消息内容", signature, keypair.public_key_hex)

# 公钥加密
ciphertext = encrypt_text("机密信息", keypair.public_key_hex)
plaintext = decrypt_text(ciphertext, keypair.private_key_hex)
```

### 完整工作流程示例

运行 `demo.py` 查看完整的使用示例，包括：
- Alice 和 Bob 之间的完整通信流程
- 签名生成与验证的完整过程
- 加密通信的端到端演示
- 错误处理和边界条件测试

```bash
python demo.py
```

### 错误处理

```python
try:
    decrypt_message("invalid_hex", keypair.private_key_hex)
except ValueError as e:
    print(f"解密失败: {e}")
```
