"""
Main demonstration script for the image watermarking system
"""

import os
import cv2
import numpy as np
from watermark_system import embed_watermark, extract_watermark
from watermark_test import WatermarkRobustnessTest
from image_transforms import apply_transformations


def create_demo_images():
    # Create demo images for testing
    demo_image = np.zeros((400, 600, 3), dtype=np.uint8)
    demo_image[:200, :] = [100, 150, 200]
    demo_image[200:, :] = [150, 200, 100]
    cv2.rectangle(demo_image, (50, 50), (200, 150), (255, 100, 50), -1)
    cv2.circle(demo_image, (450, 100), 60, (50, 100, 255), -1)
    cv2.ellipse(demo_image, (300, 300), (80, 40), 0, 0, 360, (255, 255, 100), -1)
    cv2.putText(demo_image, "DEMO IMAGE", (200, 250), cv2.FONT_HERSHEY_SIMPLEX, 1.2, (255, 255, 255), 2)
    cv2.imwrite("demo_image.jpg", demo_image)
    print("Created demo image: demo_image.jpg")
    watermark = np.ones((60, 100, 3), dtype=np.uint8) * 255
    cv2.putText(watermark, "SDU", (10, 40), cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 0, 0), 2)
    cv2.rectangle(watermark, (5, 5), (95, 55), (0, 0, 0), 2)
    cv2.imwrite("watermark.jpg", watermark)
    print("Created watermark: watermark.jpg")
    return "demo_image.jpg", "watermark.jpg"


def demo_basic_watermarking():
    print("\n" + "="*50)
    print("    BASIC WATERMARKING DEMONSTRATION")
    print("="*50)
    image_path, watermark_path = create_demo_images()
    watermarked_path = "watermarked_demo.jpg"
    print(f"\nEmbedding watermark from '{watermark_path}' into '{image_path}'...")
    success = embed_watermark(image_path, watermark_path, watermarked_path, alpha=0.2)
    if success:
        print(f"Watermark embedded successfully! Saved as: {watermarked_path}")
    else:
        print("Failed to embed watermark")
        return
    extracted_path = "extracted_demo.jpg"
    print(f"\nExtracting watermark from '{watermarked_path}'...")
    success = extract_watermark(watermarked_path, extracted_path, image_path)
    if success:
        print(f"Watermark extracted successfully! Saved as: {extracted_path}")
    else:
        print("Failed to extract watermark")
        return
    print("\nBasic demonstration completed!")
    print(f"   Original image:     {image_path}")
    print(f"   Watermark:         {watermark_path}")
    print(f"   Watermarked image: {watermarked_path}")
    print(f"   Extracted watermark: {extracted_path}")


def demo_robustness_test():
    print("\n" + "="*50)
    print("    ROBUSTNESS TESTING DEMONSTRATION")
    print("="*50)
    if not os.path.exists("demo_image.jpg") or not os.path.exists("watermark.jpg"):
        print("Creating demo images for robustness test...")
        create_demo_images()
    test_suite = WatermarkRobustnessTest("demo_results")
    test_suite.run_full_test_suite("demo_image.jpg", "watermark.jpg")


def demo_manual_transformations():
    print("\n" + "="*50)
    print("    MANUAL TRANSFORMATION DEMONSTRATION")
    print("="*50)
    if not os.path.exists("watermarked_demo.jpg"):
        print("Creating watermarked image for transformation test...")
        demo_basic_watermarking()
    from image_transforms import ImageTransformer
    watermarked_image = cv2.imread("watermarked_demo.jpg")
    original_watermark = cv2.imread("watermark.jpg")
    if watermarked_image is None:
        print("Could not load watermarked image")
        return
    transformations = {
        "Horizontal Flip": ImageTransformer.horizontal_flip(watermarked_image),
        "Crop 75%": ImageTransformer.crop(watermarked_image, 0.75),
        "High Contrast": ImageTransformer.adjust_contrast(watermarked_image, 1.8, 20),
        "JPEG 60%": ImageTransformer.compress_jpeg(watermarked_image, 60)
    }
    print("\nTesting specific transformations:")
    print("-" * 40)
    for name, transformed_img in transformations.items():
        transformed_path = f"transformed_{name.lower().replace(' ', '_').replace('%', '')}.jpg"
        cv2.imwrite(transformed_path, transformed_img)
        extracted_path = f"extracted_{name.lower().replace(' ', '_').replace('%', '')}.jpg"
        success = extract_watermark(transformed_path, extracted_path, "demo_image.jpg")
        if success and os.path.exists(extracted_path):
            extracted_wm = cv2.imread(extracted_path)
            if extracted_wm is not None and original_watermark is not None:
                from watermark_test import WatermarkQualityEvaluator
                evaluator = WatermarkQualityEvaluator()
                ncc = evaluator.calculate_ncc(original_watermark, extracted_wm)
                quality = "Good" if ncc > 0.7 else "Fair" if ncc > 0.4 else "Poor"
                print(f"{name:15} | NCC: {ncc:6.3f} | {quality}")
            else:
                print(f"{name:15} | Could not evaluate quality")
        else:
            print(f"{name:15} | Extraction failed")


def display_help():
    print("\n" + "="*60)
    print("        IMAGE WATERMARKING SYSTEM - HELP")
    print("="*60)
    print("\nThis system provides robust image watermarking capabilities")
    print("using Discrete Wavelet Transform (DWT) in the frequency domain.")
    print("\nAvailable functions:")
    print("\n1. embed_watermark(image_path, watermark_path, output_path, alpha=0.1)")
    print("   - Embeds a watermark into an image")
    print("   - alpha: watermark strength (0.05-0.3, higher = more visible)")
    print("\n2. extract_watermark(watermarked_path, output_path, original_path=None)")
    print("   - Extracts watermark from a watermarked image")
    print("   - original_path: optional, improves extraction quality")
    print("\nRobust against:")
    print("   Horizontal/Vertical flipping")
    print("   Translation (image shifting)")
    print("   Cropping (partial content removal)")
    print("   Contrast adjustment")
    print("   JPEG compression")
    print("   Rotation (small angles)")
    print("   Noise addition")
    print("\nExample usage:")
    print("   from watermark_system import embed_watermark, extract_watermark")
    print("   embed_watermark('photo.jpg', 'logo.jpg', 'watermarked.jpg')")
    print("   extract_watermark('watermarked.jpg', 'extracted_logo.jpg')")
    print("\nTo run tests:")
    print("   python watermark_test.py")


def main():
    while True:
        print("\n" + "="*60)
        print("        IMAGE WATERMARKING SYSTEM - SDU 2025")
        print("="*60)
        print("\nSelect an option:")
        print("1. Basic Watermarking Demo")
        print("2. Full Robustness Test")
        print("3. Manual Transformation Test")
        print("4. Help & Documentation")
        print("5. Exit")
        try:
            choice = input("\nEnter your choice (1-5): ").strip()
            if choice == "1":
                demo_basic_watermarking()
            elif choice == "2":
                demo_robustness_test()
            elif choice == "3":
                demo_manual_transformations()
            elif choice == "4":
                display_help()
            elif choice == "5":
                print("\nGoodbye!")
                break
            else:
                print("\nInvalid choice. Please select 1-5.")
        except KeyboardInterrupt:
            print("\n\nGoodbye!")
            break
        except Exception as e:
            print(f"\nError: {str(e)}")
        input("\nPress Enter to continue...")


if __name__ == "__main__":
    main()
