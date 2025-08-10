# Project 1: SM4 Cipher Implementation and Optimization

国密 SM4 算法的软件实现和优化

# 项目简介

`project_1` 文件夹实现了 SM4 加密算法的多种优化版本，包括基础实现、基于 AES-NI 指令集、GFNI 指令集以及查找表（T-Table）加速方法。每种实现均有独立的源代码和可执行文件，便于性能和功能对比。

## 主要内容
- `sm4.cpp` ：基础 SM4 算法实现。
- `sm4_aesni_implementation/sm4_aesni.cpp` ：基于 AES-NI 指令集的 SM4 优化实现。
- `sm4_gfni_implementation/sm4_gfni.cpp` ：基于 GFNI 指令集的 SM4 优化实现。
- `sm4_t_table_implementation/sm4_t_table.cpp` ：查找表加速的 SM4 实现。

## 编译方法
在 `project_1` 目录下，运行以下命令可自动编译所有实现并进行测试：

```bash
bash build_and_test.sh
```

如需单独编译某个实现，例如基础 SM4 实现，可使用如下命令：

```bash
g++ sm4.cpp -o sm4.elf
```

其他实现请参考 `build_and_test.sh`，使用类似的编译命令。

## 使用说明
编译后可直接运行生成的可执行文件，具体参数和用法请参考各实现的源码注释。

本项目适合用于学习 SM4 算法原理、不同优化方式的实现，以及性能对比分析。