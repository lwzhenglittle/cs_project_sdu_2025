# 图像水印系统

本项目实现了一个基于离散小波变换（DWT）的鲁棒性图像水印系统，支持在频域中嵌入和提取水印，具备较好的不可见性和抗多种图像变换的能力。

## 项目结构
- `watermark_system.py`：水印嵌入与提取的核心算法
- `image_transforms.py`：常见图像变换工具
- `watermark_test.py`：水印鲁棒性测试脚本
- `main.py`：演示与主程序入口
- `requirements.txt`：依赖库列表

## 安装与运行
1. 安装依赖：
   ```bash
   cd project_2
   pip install -r requirements.txt
   ```
2. 运行主程序：
   ```bash
   python main.py
   ```
3. 运行测试：
   ```bash
   python watermark_test.py
   ```

## 用法说明

### 水印嵌入
使用 `embed_watermark` 函数将水印嵌入到原始图像中：
```python
from watermark_system import embed_watermark
embed_watermark('photo.jpg', 'watermark.jpg', 'watermarked.jpg', alpha=0.1)
```
- `photo.jpg`：原始图像路径
- `watermark.jpg`：水印图像路径
- `watermarked.jpg`：输出含水印图像路径
- `alpha`：水印强度，数值越高水印越明显

### 水印提取
使用 `extract_watermark` 函数从含水印图像中提取水印：
```python
from watermark_system import extract_watermark
extract_watermark('watermarked.jpg', 'extracted.jpg', 'photo.jpg')
```
- `watermarked.jpg`：含水印图像路径
- `extracted.jpg`：输出提取水印路径
- `photo.jpg`：原始图像路径（可选，提供后可提升提取质量）

### 鲁棒性测试
运行 `watermark_test.py` 可自动对多种图像变换进行水印鲁棒性测试。

## 技术原理

1. **水印嵌入过程**
   - 将原始图像和水印图像转换为合适格式（如灰度或二值图）
   - 对原始图像进行两级 DWT 分解，获得低频子带（LL）
   - 在低频子带中嵌入水印信息，利用水印强度参数控制嵌入效果
   - 进行逆 DWT 重构，生成含水印图像

2. **水印提取过程**
   - 对含水印图像进行两级 DWT 分解，获得低频子带
   - 从低频子带中提取水印信息
   - 可选地结合原始图像提升提取质量
   - 对提取结果进行形态学处理，增强水印可读性

3. **鲁棒性设计**
   - 在 DWT 域低频系数中嵌入水印，提升对常见图像变换（如翻转、裁剪、压缩等）的抗性
   - 支持多通道冗余嵌入，提高水印的稳定性
   - 水印强度参数可调节，平衡不可见性与鲁棒性

4. **质量评估**
   - 系统内置 PSNR、SSIM、NCC 等指标，用于评估水印嵌入后图像质量及水印提取效果

如需详细参数和扩展用法，请参考各模块源码及注释。