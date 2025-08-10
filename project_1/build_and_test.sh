#!/bin/bash
# This script builds the project and runs tests

echo "Building SM4 implementations..."

# Build the basic implementation
echo "1. Building basic SM4..."
g++ -O2 -o sm4.elf sm4.cpp

# Build the AESNI implementation  
echo "2. Building AESNI SM4..."
g++ -O2 -msse4.2 -mavx2 -maes -o sm4_aesni.elf sm4_aesni_implementation/sm4_aesni.cpp

# Build the T-table implementation
echo "3. Building T-table SM4..."
g++ -O2 -o sm4_t_table.elf sm4_t_table_implementation/sm4_t_table.cpp

# Build the GFNI implementation
echo "4. Building GFNI SM4..."
g++ -O2 -mavx2 -mgfni -o sm4_gfni.elf sm4_gfni_implementation/sm4_gfni.cpp

echo ""
echo "Running tests..."

# Test vectors
echo "Test vector: Key=0123456789abcdeffedcba9876543210, Plaintext=0123456789abcdeffedcba9876543210"
echo "Expected ciphertext: 681edf34d206965e86b3e94f536e4246"
echo ""

echo "Testing basic SM4..."
echo " encrypt
0123456789abcdeffedcba9876543210
0123456789abcdeffedcba9876543210" | ./sm4.elf

echo ""
echo "Testing AESNI SM4..."
echo " encrypt
0123456789abcdeffedcba9876543210
0123456789abcdeffedcba9876543210" | ./sm4_aesni.elf

echo ""
echo "Testing T-table SM4..."
echo " encrypt
0123456789abcdeffedcba9876543210
0123456789abcdeffedcba9876543210" | ./sm4_t_table.elf

echo ""
echo "Testing GFNI SM4..."
echo " encrypt
0123456789abcdeffedcba9876543210
0123456789abcdeffedcba9876543210" | ./sm4_gfni.elf

echo ""
echo "Build and test complete!"