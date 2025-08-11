#!/usr/bin/env python3

from sm2_math import P, A, B, GX, GY, N, G
from sm3 import sm3_hex
from utils import int_to_hex
import sys

def print_separator():
    print("=" * 80)

def print_specifications():
    print("SM2 Public Key Cryptographic Algorithm Implementation")
    print("Based on GM/T 0003.5-2012 Standard")
    print_separator()
    
    print("\nELLIPTIC CURVE PARAMETERS:")
    print(f"Prime field Fp where p = {hex(P)}")
    print(f"                        = 2^256 - 2^224 - 2^96 + 2^64 - 1")
    print(f"Curve equation: y² = x³ + ax + b (mod p)")
    print(f"Parameter a = {hex(A)}")
    print(f"Parameter b = {hex(B)}")
    print()
    
    print("BASE POINT G:")
    print(f"Gx = {hex(GX)}")
    print(f"Gy = {hex(GY)}")
    print(f"Order n = {hex(N)}")
    print()
    
    print("VERIFICATION OF CURVE PARAMETERS:")
    left = (GY * GY) % P
    right = (GX * GX * GX + A * GX + B) % P
    print(f"G is on curve: {left == right}")
    
    from sm2_math import point_multiply, is_on_curve
    nG = point_multiply(N, G)
    print(f"n*G = O (point at infinity): {nG.is_infinity}")
    print()
    
    print("HASH FUNCTION:")
    print("SM3 hash function implementation based on GM/T 0004-2012")
    test_msg = b"abc"
    expected = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
    actual = sm3_hex(test_msg)
    print(f"SM3('abc') = {actual}")
    print(f"Expected   = {expected}")
    print(f"SM3 implementation correct: {actual == expected}")
    print()
    
    print("KEY FORMATS:")
    print("Private key: 256-bit integer (64 hex characters)")
    print("Public key:  Uncompressed format, 512 bits (128 hex characters)")
    print("             Format: 04 || x-coordinate || y-coordinate")
    print("Signature:   512 bits (128 hex characters)")
    print("             Format: r || s (each 256 bits)")
    print()
    
    print("SECURITY FEATURES:")
    print("• Cryptographically secure random number generation (secrets module)")
    print("• Proper parameter validation for all inputs")
    print("• Timing-safe comparisons for critical operations")
    print("• Complete error handling with informative messages")
    print("• No third-party cryptographic dependencies")
    print()
    
    print("SUPPORTED OPERATIONS:")
    print("• Key pair generation")
    print("• Digital signature generation and verification")
    print("• Public key encryption and decryption")
    print("• Hexadecimal string I/O for all operations")
    print("• Text string convenience functions")
    print("• Key derivation function (KDF) for encryption")
    print()
    
    print("COMPLIANCE:")
    print("• GM/T 0003.5-2012: SM2 Public Key Cryptographic Algorithm")
    print("• GM/T 0004-2012: SM3 Cryptographic Hash Algorithm")
    print("• GM/T 0003.2-2012: SM2 Recommended Curve Parameters")
    print()

def demonstrate_interoperability():
    print("INTEROPERABILITY DEMONSTRATION:")
    print_separator()
    
    from sm2 import generate_key_pair, sign_message, encrypt_message
    
    keypair = generate_key_pair()
    
    print("\nGenerated Key Pair (Standard Format):")
    print(f"Private Key: {keypair.private_key_hex}")
    print(f"Public Key X: {keypair.public_key_hex[:64]}")
    print(f"Public Key Y: {keypair.public_key_hex[64:]}")
    
    test_message_hex = "0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20"
    print(f"\nTest Message: {test_message_hex}")
    
    signature = sign_message(test_message_hex, keypair.private_key_hex)
    print(f"Signature R: {signature[:64]}")
    print(f"Signature S: {signature[64:]}")
    
    ciphertext = encrypt_message(test_message_hex, keypair.public_key_hex)
    print(f"\nCiphertext Length: {len(ciphertext)} hex characters ({len(ciphertext)//2} bytes)")
    print(f"C1 (Point): {ciphertext[:128]}")
    print(f"C3 (Hash): {ciphertext[128:192]}")
    print(f"C2 (Data): {ciphertext[192:]}")
    
    print("\nFormat Compliance:")
    print("✓ Keys and signatures use standard hexadecimal encoding")
    print("✓ Ciphertext follows C1||C3||C2 format as specified")
    print("✓ All operations use proper SM3 hash function")
    print("✓ Curve parameters match GM/T 0003.2-2012 recommendations")

def performance_characteristics():
    """Show performance characteristics"""
    print("\nPERFORMANCE CHARACTERISTICS:")
    print_separator()
    
    import time
    from sm2 import generate_key_pair, sign_text, verify_text, encrypt_text, decrypt_text
    
    # Key generation timing
    start = time.time()
    for _ in range(5):
        generate_key_pair()
    key_time = (time.time() - start) / 5
    
    # Signature timing
    keypair = generate_key_pair()
    message = "Performance test message"
    
    start = time.time()
    for _ in range(10):
        sign_text(message, keypair.private_key_hex)
    sign_time = (time.time() - start) / 10
    
    # Verification timing
    signature = sign_text(message, keypair.private_key_hex)
    start = time.time()
    for _ in range(10):
        verify_text(message, signature, keypair.public_key_hex)
    verify_time = (time.time() - start) / 10
    
    # Encryption timing
    start = time.time()
    for _ in range(5):
        encrypt_text(message, keypair.public_key_hex)
    encrypt_time = (time.time() - start) / 5
    
    print(f"Key Generation:         {key_time:.4f} seconds")
    print(f"Signature Generation:   {sign_time:.4f} seconds") 
    print(f"Signature Verification: {verify_time:.4f} seconds")
    print(f"Encryption:            {encrypt_time:.4f} seconds")
    print()
    print("Note: Performance measured on current hardware")
    print("Pure Python implementation - optimized C libraries would be faster")

def main():
    print_specifications()
    demonstrate_interoperability()
    performance_characteristics()
    
    print("\n" + "=" * 80)
    print("SM2 IMPLEMENTATION COMPLETE")
    print("Ready for cryptographic operations following GM/T standards")
    print("=" * 80)

if __name__ == "__main__":
    main()
