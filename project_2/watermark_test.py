"""
Testing module for the watermarking system
Tests robustness against various image transformations
"""

import os
import cv2
import numpy as np
from typing import List, Dict, Tuple
import matplotlib.pyplot as plt
from watermark_system import embed_watermark, extract_watermark
from image_transforms import apply_transformations, ImageTransformer


class WatermarkQualityEvaluator:
    # Evaluate watermark extraction quality
    @staticmethod
    def calculate_psnr(original: np.ndarray, extracted: np.ndarray) -> float:
        # Calculate Peak Signal-to-Noise Ratio
        if original.shape != extracted.shape:
            extracted = cv2.resize(extracted, (original.shape[1], original.shape[0]))
        if len(original.shape) == 3:
            original = cv2.cvtColor(original, cv2.COLOR_BGR2GRAY)
        if len(extracted.shape) == 3:
            extracted = cv2.cvtColor(extracted, cv2.COLOR_BGR2GRAY)
        mse = np.mean((original.astype(np.float32) - extracted.astype(np.float32)) ** 2)
        if mse == 0:
            return float('inf')
        max_pixel = 255.0
        psnr = 20 * np.log10(max_pixel / np.sqrt(mse))
        return psnr

    @staticmethod
    def calculate_ssim(original: np.ndarray, extracted: np.ndarray) -> float:
        # Calculate Structural Similarity Index
        if original.shape != extracted.shape:
            extracted = cv2.resize(extracted, (original.shape[1], original.shape[0]))
        if len(original.shape) == 3:
            original = cv2.cvtColor(original, cv2.COLOR_BGR2GRAY)
        if len(extracted.shape) == 3:
            extracted = cv2.cvtColor(extracted, cv2.COLOR_BGR2GRAY)
        img1 = original.astype(np.float32)
        img2 = extracted.astype(np.float32)
        mu1 = np.mean(img1)
        mu2 = np.mean(img2)
        sigma1_sq = np.var(img1)
        sigma2_sq = np.var(img2)
        sigma12 = np.mean((img1 - mu1) * (img2 - mu2))
        c1 = (0.01 * 255) ** 2
        c2 = (0.03 * 255) ** 2
        numerator = (2 * mu1 * mu2 + c1) * (2 * sigma12 + c2)
        denominator = (mu1 ** 2 + mu2 ** 2 + c1) * (sigma1_sq + sigma2_sq + c2)
        ssim = numerator / denominator
        return ssim

    @staticmethod
    def calculate_ncc(original: np.ndarray, extracted: np.ndarray) -> float:
        # Calculate Normalized Cross Correlation
        if original.shape != extracted.shape:
            extracted = cv2.resize(extracted, (original.shape[1], original.shape[0]))
        if len(original.shape) == 3:
            original = cv2.cvtColor(original, cv2.COLOR_BGR2GRAY)
        if len(extracted.shape) == 3:
            extracted = cv2.cvtColor(extracted, cv2.COLOR_BGR2GRAY)
        orig_flat = original.flatten().astype(np.float32)
        extr_flat = extracted.flatten().astype(np.float32)
        ncc = np.corrcoef(orig_flat, extr_flat)[0, 1]
        return ncc if not np.isnan(ncc) else 0.0


class WatermarkRobustnessTest:
    # Main class for testing watermark robustness
    def __init__(self, test_dir: str = "test_results"):
        self.test_dir = test_dir
        self.evaluator = WatermarkQualityEvaluator()
        os.makedirs(test_dir, exist_ok=True)

    def create_test_images(self) -> Tuple[str, str]:
        # Create sample test image and watermark if they don't exist
        test_image_path = os.path.join(self.test_dir, "test_image.jpg")
        watermark_path = os.path.join(self.test_dir, "watermark.jpg")
        if not os.path.exists(test_image_path):
            test_image = np.zeros((400, 600, 3), dtype=np.uint8)
            cv2.rectangle(test_image, (50, 50), (250, 150), (255, 100, 100), -1)
            cv2.circle(test_image, (400, 200), 80, (100, 255, 100), -1)
            cv2.rectangle(test_image, (300, 300), (550, 350), (100, 100, 255), -1)
            cv2.putText(test_image, "TEST IMAGE", (200, 300), cv2.FONT_HERSHEY_SIMPLEX, 1, (255, 255, 255), 2)
            cv2.imwrite(test_image_path, test_image)
            print(f"Created test image: {test_image_path}")
        if not os.path.exists(watermark_path):
            watermark = np.ones((80, 120, 3), dtype=np.uint8) * 255
            cv2.putText(watermark, "WM", (30, 50), cv2.FONT_HERSHEY_SIMPLEX, 1.5, (0, 0, 0), 3)
            cv2.circle(watermark, (80, 25), 15, (0, 0, 0), 2)
            cv2.imwrite(watermark_path, watermark)
            print(f"Created watermark: {watermark_path}")
        return test_image_path, watermark_path

    def run_basic_test(self, test_image_path: str, watermark_path: str) -> bool:
        # Run basic watermark embedding and extraction test
        print("\n=== Running Basic Watermark Test ===")
        watermarked_path = os.path.join(self.test_dir, "watermarked_basic.jpg")
        extracted_path = os.path.join(self.test_dir, "extracted_basic.jpg")
        print("Embedding watermark...")
        success = embed_watermark(test_image_path, watermark_path, watermarked_path)
        if not success:
            print("Failed to embed watermark")
            return False
        print("Watermark embedded successfully")
        print("Extracting watermark...")
        success = extract_watermark(watermarked_path, extracted_path, test_image_path)
        if not success:
            print("Failed to extract watermark")
            return False
        print("Watermark extracted successfully")
        original_wm = cv2.imread(watermark_path)
        extracted_wm = cv2.imread(extracted_path)
        if original_wm is not None and extracted_wm is not None:
            psnr = self.evaluator.calculate_psnr(original_wm, extracted_wm)
            ssim = self.evaluator.calculate_ssim(original_wm, extracted_wm)
            ncc = self.evaluator.calculate_ncc(original_wm, extracted_wm)
            print(f"Quality Metrics:")
            print(f"  PSNR: {psnr:.2f} dB")
            print(f"  SSIM: {ssim:.4f}")
            print(f"  NCC:  {ncc:.4f}")
        return True

    def run_robustness_test(self, test_image_path: str, watermark_path: str) -> Dict[str, Dict[str, float]]:
        # Run comprehensive robustness test against various transformations
        print("\n=== Running Robustness Test ===")
        watermarked_path = os.path.join(self.test_dir, "watermarked_robustness.jpg")
        success = embed_watermark(test_image_path, watermark_path, watermarked_path, alpha=0.15)
        if not success:
            print("Failed to embed watermark for robustness test")
            return {}
        transform_dir = os.path.join(self.test_dir, "transformations")
        print("Applying transformations...")
        transformed_paths = apply_transformations(watermarked_path, transform_dir)
        results = {}
        original_wm = cv2.imread(watermark_path)
        print("\nTesting watermark extraction on transformed images:")
        print("-" * 60)
        for i, transformed_path in enumerate(transformed_paths):
            transform_name = os.path.basename(transformed_path).replace('.jpg', '').replace('watermarked_robustness_', '')
            extracted_path = os.path.join(self.test_dir, f"extracted_{transform_name}.jpg")
            success = extract_watermark(transformed_path, extracted_path, test_image_path)
            if success and os.path.exists(extracted_path):
                extracted_wm = cv2.imread(extracted_path)
                if extracted_wm is not None:
                    psnr = self.evaluator.calculate_psnr(original_wm, extracted_wm)
                    ssim = self.evaluator.calculate_ssim(original_wm, extracted_wm)
                    ncc = self.evaluator.calculate_ncc(original_wm, extracted_wm)
                    results[transform_name] = {
                        'psnr': psnr,
                        'ssim': ssim,
                        'ncc': ncc,
                        'success': True
                    }
                    quality = "Good" if ncc > 0.7 else "Fair" if ncc > 0.4 else "Poor"
                    print(f"{transform_name:20} | NCC: {ncc:6.3f} | PSNR: {psnr:6.2f} dB | {quality}")
                else:
                    results[transform_name] = {'success': False}
                    print(f"{transform_name:20} | Extraction failed")
            else:
                results[transform_name] = {'success': False}
                print(f"{transform_name:20} | Extraction failed")
        return results

    def generate_report(self, results: Dict[str, Dict[str, float]]) -> None:
        # Generate a detailed report of the robustness test results
        print("\n" + "=" * 70)
        print("                    WATERMARK ROBUSTNESS REPORT")
        print("=" * 70)
        if not results:
            print("No test results to report.")
            return
        categories = {
            'Geometric': ['horizontal_flip', 'vertical_flip', 'translate_10_10', 'translate_-15_20', 'rotate_5', 'rotate_-10'],
            'Cropping': ['crop_80', 'crop_70'],
            'Quality': ['contrast_150', 'contrast_80', 'jpeg_90', 'jpeg_50'],
            'Noise': ['noise_light', 'noise_moderate']
        }
        overall_stats = {'total': 0, 'successful': 0, 'good_quality': 0}
        for category, transforms in categories.items():
            print(f"\n{category} Transformations:")
            print("-" * 40)
            category_stats = {'total': 0, 'successful': 0, 'good_quality': 0}
            for transform in transforms:
                if transform in results:
                    result = results[transform]
                    category_stats['total'] += 1
                    overall_stats['total'] += 1
                    if result.get('success', False):
                        category_stats['successful'] += 1
                        overall_stats['successful'] += 1
                        ncc = result.get('ncc', 0)
                        if ncc > 0.7:
                            category_stats['good_quality'] += 1
                            overall_stats['good_quality'] += 1
                        print(f"  {transform:18} | NCC: {ncc:6.3f}")
                    else:
                        print(f"  {transform:18} | Failed")
            if category_stats['total'] > 0:
                success_rate = (category_stats['successful'] / category_stats['total']) * 100
                quality_rate = (category_stats['good_quality'] / category_stats['total']) * 100
                print(f"  Summary: {success_rate:.1f}% success, {quality_rate:.1f}% good quality")
        print("\n" + "=" * 70)
        print("OVERALL SUMMARY:")
        print("=" * 70)
        if overall_stats['total'] > 0:
            overall_success = (overall_stats['successful'] / overall_stats['total']) * 100
            overall_quality = (overall_stats['good_quality'] / overall_stats['total']) * 100
            print(f"Total tests:        {overall_stats['total']}")
            print(f"Successful extractions: {overall_stats['successful']} ({overall_success:.1f}%)")
            print(f"Good quality extractions: {overall_stats['good_quality']} ({overall_quality:.1f}%)")
            if overall_success >= 80 and overall_quality >= 60:
                rating = "EXCELLENT - Highly robust watermarking system"
            elif overall_success >= 60 and overall_quality >= 40:
                rating = "GOOD - Reasonably robust watermarking system"
            elif overall_success >= 40:
                rating = "FAIR - Limited robustness, needs improvement"
            else:
                rating = "POOR - Low robustness, significant improvements needed"
            print(f"\nOverall Rating: {rating}")
        print("\n" + "=" * 70)

    def run_full_test_suite(self, test_image_path: str = None, watermark_path: str = None) -> None:
        # Run the complete test suite
        print("Starting Watermark Robustness Test Suite")
        print("=" * 70)
        if not test_image_path or not watermark_path:
            test_image_path, watermark_path = self.create_test_images()
        basic_success = self.run_basic_test(test_image_path, watermark_path)
        if not basic_success:
            print("Basic test failed. Stopping test suite.")
            return
        results = self.run_robustness_test(test_image_path, watermark_path)
        self.generate_report(results)
        print(f"\nTest results saved in: {os.path.abspath(self.test_dir)}")
        print("Test suite completed!")


def main():
    # Main function to run the watermark robustness tests
    test_suite = WatermarkRobustnessTest("test_results")
    test_suite.run_full_test_suite()


if __name__ == "__main__":
    main()
