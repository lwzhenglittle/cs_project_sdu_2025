"""
Image transformation utilities for watermark robustness testing
"""

import cv2
import numpy as np
from typing import Tuple, List
import os


class ImageTransformer:
    # Various transformations for watermark robustness testing
    @staticmethod
    def horizontal_flip(image: np.ndarray) -> np.ndarray:
        return cv2.flip(image, 1)
    @staticmethod
    def vertical_flip(image: np.ndarray) -> np.ndarray:
        return cv2.flip(image, 0)
    @staticmethod
    def translate(image: np.ndarray, tx: int, ty: int) -> np.ndarray:
        rows, cols = image.shape[:2]
        M = np.float32([[1, 0, tx], [0, 1, ty]])
        return cv2.warpAffine(image, M, (cols, rows))
    @staticmethod
    def crop(image: np.ndarray, crop_ratio: float = 0.8) -> np.ndarray:
        h, w = image.shape[:2]
        new_h, new_w = int(h * crop_ratio), int(w * crop_ratio)
        start_h = (h - new_h) // 2
        start_w = (w - new_w) // 2
        cropped = image[start_h:start_h + new_h, start_w:start_w + new_w]
        return cv2.resize(cropped, (w, h))
    @staticmethod
    def adjust_contrast(image: np.ndarray, alpha: float = 1.5, beta: int = 0) -> np.ndarray:
        return cv2.convertScaleAbs(image, alpha=alpha, beta=beta)
    @staticmethod
    def rotate(image: np.ndarray, angle: float) -> np.ndarray:
        h, w = image.shape[:2]
        center = (w // 2, h // 2)
        M = cv2.getRotationMatrix2D(center, angle, 1.0)
        return cv2.warpAffine(image, M, (w, h))
    @staticmethod
    def add_noise(image: np.ndarray, noise_factor: float = 0.1) -> np.ndarray:
        noise = np.random.normal(0, noise_factor * 255, image.shape).astype(np.float32)
        noisy_image = image.astype(np.float32) + noise
        return np.clip(noisy_image, 0, 255).astype(np.uint8)
    @staticmethod
    def compress_jpeg(image: np.ndarray, quality: int = 70) -> np.ndarray:
        encode_param = [int(cv2.IMWRITE_JPEG_QUALITY), quality]
        _, encimg = cv2.imencode('.jpg', image, encode_param)
        return cv2.imdecode(encimg, 1)


def apply_transformations(image_path: str, output_dir: str) -> List[str]:
    # Apply all transformations to an image and save results
    image = cv2.imread(image_path)
    if image is None:
        raise ValueError(f"Could not load image: {image_path}")
    os.makedirs(output_dir, exist_ok=True)
    base_name = os.path.splitext(os.path.basename(image_path))[0]
    transformations = {
        'horizontal_flip': ImageTransformer.horizontal_flip(image),
        'vertical_flip': ImageTransformer.vertical_flip(image),
        'translate_10_10': ImageTransformer.translate(image, 10, 10),
        'translate_-15_20': ImageTransformer.translate(image, -15, 20),
        'crop_80': ImageTransformer.crop(image, 0.8),
        'crop_70': ImageTransformer.crop(image, 0.7),
        'contrast_150': ImageTransformer.adjust_contrast(image, 1.5, 10),
        'contrast_80': ImageTransformer.adjust_contrast(image, 0.8, -10),
        'rotate_5': ImageTransformer.rotate(image, 5),
        'rotate_-10': ImageTransformer.rotate(image, -10),
        'noise_light': ImageTransformer.add_noise(image, 0.05),
        'noise_moderate': ImageTransformer.add_noise(image, 0.15),
        'jpeg_90': ImageTransformer.compress_jpeg(image, 90),
        'jpeg_50': ImageTransformer.compress_jpeg(image, 50)
    }
    output_paths = []
    for transform_name, transformed_image in transformations.items():
        output_path = os.path.join(output_dir, f"{base_name}_{transform_name}.jpg")
        cv2.imwrite(output_path, transformed_image)
        output_paths.append(output_path)
    return output_paths
