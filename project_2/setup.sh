#!/bin/bash

# Image Watermarking System Setup Script
# CS Project SDU 2025 - Project 2

echo "Setting up Image Watermarking System..."
echo "=========================================="

# Check Python version
python_version=$(python3 --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
echo "Python version: $python_version"

# Install dependencies
echo "Installing Python dependencies..."
pip3 install -r requirements.txt

if [ $? -eq 0 ]; then
    echo "Dependencies installed successfully!"
else
    echo "Failed to install dependencies"
    exit 1
fi

# Test the system
echo ""
echo "Testing the watermarking system..."
python3 -c "
try:
    from watermark_system import embed_watermark, extract_watermark
    from main import create_demo_images
    print('System test passed!')
except Exception as e:
    print(f'System test failed: {e}')
    exit(1)
"

if [ $? -eq 0 ]; then
    echo ""
    echo "Setup completed successfully!"
    echo ""
    echo "Usage Instructions:"
    echo "  1. Run interactive demo:    python3 main.py"
    echo "  2. Run robustness tests:    python3 watermark_test.py"
    echo "  3. View documentation:      cat README.md"
    echo ""
    echo "Example usage:"
    echo "  from watermark_system import embed_watermark, extract_watermark"
    echo "  embed_watermark('photo.jpg', 'logo.jpg', 'watermarked.jpg')"
    echo "  extract_watermark('watermarked.jpg', 'extracted.jpg')"
    echo ""
else
    echo "Setup failed"
    exit 1
fi
