"""
Simple example demonstrating the watermark system usage
This file shows the basic API usage without the full interactive interface
"""

from watermark_system import embed_watermark, extract_watermark
from watermark_test import WatermarkQualityEvaluator
import cv2
import numpy as np
import os


def create_sample_images():
    # Create sample images for demonstration
    photo = np.zeros((300, 400, 3), dtype=np.uint8)
    photo[:, :] = [200, 220, 240]
    cv2.rectangle(photo, (50, 50), (150, 120), (100, 150, 255), -1)
    cv2.circle(photo, (300, 150), 50, (255, 150, 100), -1)
    cv2.putText(photo, "SAMPLE", (150, 200), cv2.FONT_HERSHEY_SIMPLEX, 1, (50, 50, 50), 2)
    cv2.imwrite("sample_photo.jpg", photo)
    watermark = np.ones((50, 80, 3), dtype=np.uint8) * 255
    cv2.putText(watermark, "COPY", (5, 35), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 0, 0), 2)
    cv2.rectangle(watermark, (2, 2), (78, 48), (0, 0, 0), 2)
    cv2.imwrite("sample_watermark.jpg", watermark)
    print("Created sample_photo.jpg and sample_watermark.jpg")
    return "sample_photo.jpg", "sample_watermark.jpg"


def example_basic_usage():
    # Example 1: Basic watermark embedding and extraction
    print("\n" + "="*50)
    print("EXAMPLE 1: Basic Watermark Usage")
    print("="*50)
    if not os.path.exists("sample_photo.jpg") or not os.path.exists("sample_watermark.jpg"):
        photo_path, watermark_path = create_sample_images()
    else:
        photo_path, watermark_path = "sample_photo.jpg", "sample_watermark.jpg"
    print("Embedding watermark...")
    success = embed_watermark(
        image_path=photo_path,
        watermark_path=watermark_path,
        output_path="example_watermarked.jpg",
        alpha=0.12
    )
    if success:
        print("Watermark embedded! Saved as: example_watermarked.jpg")
    else:
        print("Failed to embed watermark")
        return
    print("Extracting watermark...")
    success = extract_watermark(
        watermarked_image_path="example_watermarked.jpg",
        output_path="example_extracted.jpg",
        original_image_path=photo_path
    )
    if success:
        print("Watermark extracted! Saved as: example_extracted.jpg")
        evaluator = WatermarkQualityEvaluator()
        original = cv2.imread(watermark_path)
        extracted = cv2.imread("example_extracted.jpg")
        if original is not None and extracted is not None:
            ncc = evaluator.calculate_ncc(original, extracted)
            psnr = evaluator.calculate_psnr(original, extracted)
            print(f"Quality: NCC = {ncc:.3f}, PSNR = {psnr:.1f} dB")
    else:
        print("Failed to extract watermark")


def example_robustness_test():
    # Example 2: Test robustness against specific attacks
    print("\n" + "="*50)
    print("EXAMPLE 2: Robustness Against Attacks")
    print("="*50)
    if not os.path.exists("example_watermarked.jpg"):
        print("Please run example 1 first to create watermarked image")
        return
    from image_transforms import ImageTransformer
    watermarked = cv2.imread("example_watermarked.jpg")
    original_watermark = cv2.imread("sample_watermark.jpg")
    attacks = {
        "Horizontal Flip": ImageTransformer.horizontal_flip(watermarked),
        "75% Crop": ImageTransformer.crop(watermarked, 0.75),
        "High Contrast": ImageTransformer.adjust_contrast(watermarked, 2.0),
        "JPEG 60%": ImageTransformer.compress_jpeg(watermarked, 60)
    }
    evaluator = WatermarkQualityEvaluator()
    print("Testing robustness against attacks:")
    print("-" * 45)
    for attack_name, attacked_image in attacks.items():
        attack_path = f"attack_{attack_name.lower().replace(' ', '_').replace('%', '')}.jpg"
        cv2.imwrite(attack_path, attacked_image)
        extracted_path = f"extracted_{attack_name.lower().replace(' ', '_').replace('%', '')}.jpg"
        success = extract_watermark(attack_path, extracted_path, "sample_photo.jpg")
        if success:
            extracted = cv2.imread(extracted_path)
            if extracted is not None and original_watermark is not None:
                ncc = evaluator.calculate_ncc(original_watermark, extracted)
                quality = "Good" if ncc > 0.7 else "Fair" if ncc > 0.4 else "Poor"
                print(f"{attack_name:15} | NCC: {ncc:6.3f} | {quality}")
            else:
                print(f"{attack_name:15} | Could not evaluate")
        else:
            print(f"{attack_name:15} | Extraction failed")


def example_parameter_tuning():
    # Example 3: Demonstrate parameter effects
    print("\n" + "="*50)
    print("EXAMPLE 3: Parameter Tuning Effects")
    print("="*50)
    if not os.path.exists("sample_photo.jpg") or not os.path.exists("sample_watermark.jpg"):
        create_sample_images()
    evaluator = WatermarkQualityEvaluator()
    original_watermark = cv2.imread("sample_watermark.jpg")
    alpha_values = [0.05, 0.1, 0.15, 0.2]
    print("Testing different watermark strengths (alpha):")
    print("-" * 45)
    for alpha in alpha_values:
        watermarked_path = f"watermarked_alpha_{alpha:.2f}.jpg"
        embed_watermark("sample_photo.jpg", "sample_watermark.jpg", watermarked_path, alpha=alpha)
        extracted_path = f"extracted_alpha_{alpha:.2f}.jpg"
        success = extract_watermark(watermarked_path, extracted_path, "sample_photo.jpg")
        if success:
            extracted = cv2.imread(extracted_path)
            if extracted is not None:
                ncc = evaluator.calculate_ncc(original_watermark, extracted)
                visibility = "Low" if alpha < 0.1 else "Medium" if alpha < 0.2 else "High"
                print(f"α = {alpha:.2f} | NCC: {ncc:.3f} | Visibility: {visibility}")


def main():
    # Run all examples
    print("Image Watermarking System - Usage Examples")
    print("=" * 50)
    try:
        example_basic_usage()
        example_robustness_test()
        example_parameter_tuning()
        print("\n" + "="*50)
        print("All examples completed successfully!")
        print("\nFiles created:")
        print("  - sample_photo.jpg, sample_watermark.jpg (test images)")
        print("  - example_watermarked.jpg (watermarked image)")
        print("  - example_extracted.jpg (extracted watermark)")
        print("  - Various attack test images and extractions")
        print("\nNext steps:")
        print("  - Run 'python3 main.py' for interactive demo")
        print("  - Run 'python3 watermark_test.py' for full robustness test")
        print("  - Check README.md for detailed documentation")
    except Exception as e:
        print(f"\nExample failed: {str(e)}")
        print("Make sure all dependencies are installed: pip3 install -r requirements.txt")


if __name__ == "__main__":
    main()
