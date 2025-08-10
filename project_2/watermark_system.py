"""
Robust Image Watermarking System
Using Discrete Wavelet Transform (DWT) for frequency domain watermarking

Provides functions for embedding and extracting watermarks
from images using DWT coefficients, robust against various
image transformations.
"""

import cv2
import numpy as np
import pywt
from PIL import Image
from typing import Tuple, Optional
import os


class WatermarkEmbedder:
    # Embeds watermarks into images using DWT
    def __init__(self, wavelet='haar', alpha=0.1):
        self.wavelet = wavelet
        self.alpha = alpha
    def _prepare_watermark(self, watermark: np.ndarray, target_size: Tuple[int, int]) -> np.ndarray:
        # Resize and convert watermark to binary
        if len(watermark.shape) == 3:
            watermark = cv2.cvtColor(watermark, cv2.COLOR_BGR2GRAY)
        watermark = cv2.resize(watermark, target_size, interpolation=cv2.INTER_AREA)
        _, binary_watermark = cv2.threshold(watermark, 127, 1, cv2.THRESH_BINARY)
        return binary_watermark.astype(np.float32)
    def _embed_watermark_channel(self, channel: np.ndarray, watermark: np.ndarray) -> np.ndarray:
        # Embed watermark into a single channel using DWT
        coeffs = pywt.wavedec2(channel, self.wavelet, level=2)
        ll_coeffs = coeffs[0]
        watermark_resized = cv2.resize(watermark, (ll_coeffs.shape[1], ll_coeffs.shape[0]), interpolation=cv2.INTER_NEAREST)
        coeffs_modified = list(coeffs)
        coeffs_modified[0] = ll_coeffs + self.alpha * watermark_resized
        watermarked_channel = pywt.waverec2(coeffs_modified, self.wavelet)
        return np.clip(watermarked_channel, 0, 255).astype(np.uint8)
    def embed_watermark(self, image_path: str, watermark_path: str, output_path: str) -> bool:
        # Embed watermark into an image
        try:
            image = cv2.imread(image_path)
            watermark = cv2.imread(watermark_path)
            if image is None or watermark is None:
                raise ValueError("Could not load image or watermark")
            image_float = image.astype(np.float32)
            target_size = (image.shape[1] // 4, image.shape[0] // 4)
            binary_watermark = self._prepare_watermark(watermark, target_size)
            watermarked_image = np.zeros_like(image_float)
            for i in range(3):
                watermarked_image[:, :, i] = self._embed_watermark_channel(
                    image_float[:, :, i], binary_watermark
                )
            watermarked_image = np.clip(watermarked_image, 0, 255).astype(np.uint8)
            cv2.imwrite(output_path, watermarked_image)
            self._save_watermark_info(output_path, binary_watermark.shape, self.alpha, self.wavelet)
            return True
        except Exception as e:
            print(f"Error embedding watermark: {str(e)}")
            return False
    def _save_watermark_info(self, image_path: str, watermark_shape: Tuple[int, int], alpha: float, wavelet: str) -> None:
        # Save watermark information for extraction
        info_path = image_path.replace('.', '_info.txt')
        with open(info_path, 'w') as f:
            f.write(f"watermark_shape:{watermark_shape[0]},{watermark_shape[1]}\n")
            f.write(f"alpha:{alpha}\n")
            f.write(f"wavelet:{wavelet}\n")


class WatermarkExtractor:
    # Extracts watermarks from watermarked images
    def _load_watermark_info(self, image_path: str) -> Tuple[Tuple[int, int], float, str]:
        # Load watermark information for extraction
        info_path = image_path.replace('.', '_info.txt')
        if not os.path.exists(info_path):
            return (64, 64), 0.1, 'haar'
        watermark_shape = (64, 64)
        alpha = 0.1
        wavelet = 'haar'
        with open(info_path, 'r') as f:
            for line in f:
                if line.startswith('watermark_shape:'):
                    dims = line.split(':')[1].strip().split(',')
                    watermark_shape = (int(dims[0]), int(dims[1]))
                elif line.startswith('alpha:'):
                    alpha = float(line.split(':')[1].strip())
                elif line.startswith('wavelet:'):
                    wavelet = line.split(':')[1].strip()
        return watermark_shape, alpha, wavelet
    def _extract_watermark_channel(self, channel: np.ndarray, original_channel: np.ndarray, alpha: float, wavelet: str, watermark_shape: Tuple[int, int]) -> np.ndarray:
        # Extract watermark from a single channel using DWT
        coeffs = pywt.wavedec2(channel, wavelet, level=2)
        if original_channel is not None:
            orig_coeffs = pywt.wavedec2(original_channel, wavelet, level=2)
            watermark_coeffs = (coeffs[0] - orig_coeffs[0]) / alpha
        else:
            ll_coeffs = coeffs[0]
            watermark_coeffs = ll_coeffs
        extracted_watermark = cv2.resize(watermark_coeffs, watermark_shape, interpolation=cv2.INTER_NEAREST)
        return extracted_watermark
    def extract_watermark(self, watermarked_image_path: str, output_path: str, original_image_path: Optional[str] = None) -> bool:
        # Extract watermark from a watermarked image
        try:
            watermarked_image = cv2.imread(watermarked_image_path)
            if watermarked_image is None:
                raise ValueError("Could not load watermarked image")
            original_image = None
            if original_image_path:
                original_image = cv2.imread(original_image_path)
            watermark_shape, alpha, wavelet = self._load_watermark_info(watermarked_image_path)
            extracted_watermarks = []
            for i in range(3):
                original_channel = original_image[:, :, i].astype(np.float32) if original_image is not None else None
                extracted = self._extract_watermark_channel(
                    watermarked_image[:, :, i].astype(np.float32), 
                    original_channel, alpha, wavelet, watermark_shape
                )
                extracted_watermarks.append(extracted)
            final_watermark = np.mean(extracted_watermarks, axis=0)
            final_watermark = self._enhance_watermark(final_watermark)
            cv2.imwrite(output_path, final_watermark)
            return True
        except Exception as e:
            print(f"Error extracting watermark: {str(e)}")
            return False
    def _enhance_watermark(self, watermark: np.ndarray) -> np.ndarray:
        # Enhance the extracted watermark for better visibility
        watermark = (watermark - watermark.min()) / (watermark.max() - watermark.min()) * 255
        _, binary_watermark = cv2.threshold(watermark.astype(np.uint8), 127, 255, cv2.THRESH_BINARY)
        kernel = np.ones((3, 3), np.uint8)
        binary_watermark = cv2.morphologyEx(binary_watermark, cv2.MORPH_CLOSE, kernel)
        binary_watermark = cv2.morphologyEx(binary_watermark, cv2.MORPH_OPEN, kernel)
        return binary_watermark


def embed_watermark(image_path: str, watermark_path: str, output_path: str, alpha: float = 0.1) -> bool:
    # Embed a watermark into an image
    embedder = WatermarkEmbedder(alpha=alpha)
    return embedder.embed_watermark(image_path, watermark_path, output_path)


def extract_watermark(watermarked_image_path: str, output_path: str, original_image_path: Optional[str] = None) -> bool:
    # Extract watermark from a watermarked image
    extractor = WatermarkExtractor()
    return extractor.extract_watermark(watermarked_image_path, output_path, original_image_path)
