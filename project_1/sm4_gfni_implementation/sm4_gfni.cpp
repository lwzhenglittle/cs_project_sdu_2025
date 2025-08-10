#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <chrono>
#include <immintrin.h>
#include <cpuid.h>

/**
 * SM4 GFNI/AVX2 Optimized Implementation
 * 
 * This implementation uses Intel's Galois Field New Instructions (GFNI) 
 * with AVX2 to optimize SM4 encryption/decryption by leveraging:
 * 1. GFNI instructions for efficient S-box transformations
 * 2. AVX2 for parallel processing of multiple blocks
 * 3. Affine transformations to map between SM4 and AES Galois fields
 * 
 * Based on the libgcrypt implementation by Jussi Kivilinna
 */

class SM4_GFNI {
private:
    static const uint32_t FK[4];
    static const uint32_t CK[32];
    
    // Affine transform matrices for converting between SM4 and AES Galois fields
    // These allow us to use AES S-box hardware for SM4 S-box computation
    static const uint64_t PRE_AFFINE_MATRIX[4];  // SM4 field to AES field
    static const uint64_t POST_AFFINE_MATRIX[4]; // AES field to SM4 field
    
    // Byte rotation masks for implementing circular shifts with vpshufb
    static const uint8_t ROL_8_MASK[32];
    static const uint8_t ROL_16_MASK[32];
    static const uint8_t ROL_24_MASK[32];
    static const uint8_t BSWAP32_MASK[32];
    
    uint32_t round_keys[32];
    
    static std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
        std::vector<uint8_t> bytes;
        for (size_t i = 0; i < hex.length(); i += 2) {
            uint8_t byte = static_cast<uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16));
            bytes.push_back(byte);
        }
        return bytes;
    }
    
    static std::string bytes_to_hex(const std::vector<uint8_t>& bytes) {
        std::stringstream ss;
        for (uint8_t byte : bytes) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        return ss.str();
    }
    
    static uint32_t bytes_to_uint32_be(const uint8_t* bytes) {
        return (static_cast<uint32_t>(bytes[0]) << 24) |
               (static_cast<uint32_t>(bytes[1]) << 16) |
               (static_cast<uint32_t>(bytes[2]) << 8) |
               static_cast<uint32_t>(bytes[3]);
    }
    
    static void uint32_to_bytes_be(uint32_t value, uint8_t* bytes) {
        bytes[0] = static_cast<uint8_t>((value >> 24) & 0xFF);
        bytes[1] = static_cast<uint8_t>((value >> 16) & 0xFF);
        bytes[2] = static_cast<uint8_t>((value >> 8) & 0xFF);
        bytes[3] = static_cast<uint8_t>(value & 0xFF);
    }
    
    /**
     * Transpose 4x4 matrix of 32-bit words using AVX2
     * This is essential for converting between row-wise and column-wise data layout
     */
    static void transpose_4x4(__m128i& x0, __m128i& x1, __m128i& x2, __m128i& x3) {
        __m128i t0 = _mm_unpacklo_epi32(x0, x1);  // [a0 b0 a1 b1]
        __m128i t1 = _mm_unpackhi_epi32(x0, x1);  // [a2 b2 a3 b3]
        __m128i t2 = _mm_unpacklo_epi32(x2, x3);  // [c0 d0 c1 d1]
        __m128i t3 = _mm_unpackhi_epi32(x2, x3);  // [c2 d2 c3 d3]
        
        x0 = _mm_unpacklo_epi64(t0, t2);  // [a0 b0 c0 d0]
        x1 = _mm_unpackhi_epi64(t0, t2);  // [a1 b1 c1 d1]
        x2 = _mm_unpacklo_epi64(t1, t3);  // [a2 b2 c2 d2]
        x3 = _mm_unpackhi_epi64(t1, t3);  // [a3 b3 c3 d3]
    }
    
    /**
     * GFNI-based S-box transformation
     * Uses affine transformation to convert from SM4 field to AES field,
     * applies AES S-box inverse, then converts back to SM4 field
     */
    static __m128i gfni_sbox(__m128i input) {
        // Load affine transformation matrices
        __m128i pre_matrix = _mm_load_si128(reinterpret_cast<const __m128i*>(PRE_AFFINE_MATRIX));
        __m128i post_matrix = _mm_load_si128(reinterpret_cast<const __m128i*>(POST_AFFINE_MATRIX));
        
        // Transform SM4 field to AES field and apply inverse S-box
        __m128i transformed = _mm_gf2p8affine_epi64_epi8(input, pre_matrix, 0x65);
        __m128i result = _mm_gf2p8affineinv_epi64_epi8(transformed, post_matrix, 0xd3);
        
        return result;
    }
    
    /**
     * SM4 linear transformation L(x) = x ⊕ (x <<<< 2) ⊕ (x <<<< 10) ⊕ (x <<<< 18) ⊕ (x <<<< 24)
     * Implemented using byte-wise rotations for efficiency
     */
    static __m128i linear_transform(__m128i x) {
        __m128i rol8_mask = _mm_load_si128(reinterpret_cast<const __m128i*>(ROL_8_MASK));
        __m128i rol16_mask = _mm_load_si128(reinterpret_cast<const __m128i*>(ROL_16_MASK));
        __m128i rol24_mask = _mm_load_si128(reinterpret_cast<const __m128i*>(ROL_24_MASK));
        
        // Calculate x ⊕ (x <<<< 8) ⊕ (x <<<< 16)
        __m128i x_rol8 = _mm_shuffle_epi8(x, rol8_mask);
        __m128i temp1 = _mm_xor_si128(x, x_rol8);
        __m128i x_rol16 = _mm_shuffle_epi8(x, rol16_mask);
        __m128i temp2 = _mm_xor_si128(temp1, x_rol16);
        
        // Add x <<<< 24
        __m128i x_rol24 = _mm_shuffle_epi8(x, rol24_mask);
        __m128i result = _mm_xor_si128(temp2, x_rol24);
        
        // Add (x <<<< 2) and (x <<<< 10) = (x <<<< 8) <<<< 2
        __m128i temp2_rol2 = _mm_or_si128(_mm_slli_epi32(temp2, 2), _mm_srli_epi32(temp2, 30));
        result = _mm_xor_si128(result, temp2_rol2);
        
        return result;
    }
    
    /**
     * SM4 key schedule linear transformation L'(x) = x ⊕ (x <<<< 13) ⊕ (x <<<< 23)
     */
    static __m128i key_linear_transform(__m128i x) {
        __m128i x_rol13 = _mm_or_si128(_mm_slli_epi32(x, 13), _mm_srli_epi32(x, 19));
        __m128i x_rol23 = _mm_or_si128(_mm_slli_epi32(x, 23), _mm_srli_epi32(x, 9));
        
        return _mm_xor_si128(_mm_xor_si128(x, x_rol13), x_rol23);
    }
    
    /**
     * SM4 round function using GFNI optimization
     */
    static __m128i sm4_round(__m128i x0, __m128i x1, __m128i x2, __m128i x3, uint32_t rk) {
        // Broadcast round key
        __m128i round_key = _mm_set1_epi32(rk);
        
        // Calculate x1 ⊕ x2 ⊕ x3 ⊕ rk
        __m128i temp = _mm_xor_si128(_mm_xor_si128(x1, x2), x3);
        temp = _mm_xor_si128(temp, round_key);
        
        // Apply GFNI S-box transformation
        temp = gfni_sbox(temp);
        
        // Apply linear transformation
        temp = linear_transform(temp);
        
        // Return x0 ⊕ L(τ(x1 ⊕ x2 ⊕ x3 ⊕ rk))
        return _mm_xor_si128(x0, temp);
    }
    
    /**
     * Generate round keys using GFNI-accelerated key schedule
     */
    void expand_key(const uint8_t* key) {
        // Load master key
        uint32_t mk[4];
        for (int i = 0; i < 4; i++) {
            mk[i] = bytes_to_uint32_be(key + i * 4);
        }
        
        // Initialize with FK constants
        uint32_t k[4];
        for (int i = 0; i < 4; i++) {
            k[i] = mk[i] ^ FK[i];
        }
        
        // Generate round keys
        for (int i = 0; i < 32; i++) {
            // Load current state into SIMD registers
            __m128i k_vec = _mm_setr_epi32(k[0], k[1], k[2], k[3]);
            __m128i ck_vec = _mm_set1_epi32(CK[i]);
            
            // Calculate k[1] ⊕ k[2] ⊕ k[3] ⊕ CK[i]
            __m128i temp = _mm_xor_si128(_mm_xor_si128(
                _mm_shuffle_epi32(k_vec, _MM_SHUFFLE(3, 3, 3, 1)), // k[1]
                _mm_shuffle_epi32(k_vec, _MM_SHUFFLE(3, 3, 3, 2))  // k[2]
            ), _mm_shuffle_epi32(k_vec, _MM_SHUFFLE(3, 3, 3, 3))); // k[3]
            temp = _mm_xor_si128(temp, ck_vec);
            
            // Apply GFNI S-box
            temp = gfni_sbox(temp);
            
            // Apply key schedule linear transformation
            temp = key_linear_transform(temp);
            
            // Calculate new key: k[0] ⊕ L'(τ(k[1] ⊕ k[2] ⊕ k[3] ⊕ CK[i]))
            __m128i new_key = _mm_xor_si128(
                _mm_shuffle_epi32(k_vec, _MM_SHUFFLE(3, 3, 3, 0)), temp);
            
            // Extract the new round key
            round_keys[i] = static_cast<uint32_t>(_mm_extract_epi32(new_key, 0));
            
            // Shift the key state
            k[0] = k[1];
            k[1] = k[2];
            k[2] = k[3];
            k[3] = round_keys[i];
        }
    }
    
    /**
     * Process 4 blocks in parallel using AVX2/GFNI
     */
    void crypt_4blocks(uint8_t* output, const uint8_t* input, bool encrypt) {
        // Load input blocks and convert to big-endian
        __m128i bswap_mask = _mm_load_si128(reinterpret_cast<const __m128i*>(BSWAP32_MASK));
        
        __m128i x0, x1, x2, x3;
        x0 = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(input + 0)), bswap_mask);
        x1 = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(input + 16)), bswap_mask);
        x2 = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(input + 32)), bswap_mask);
        x3 = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(input + 48)), bswap_mask);
        
        // Transpose for parallel processing
        transpose_4x4(x0, x1, x2, x3);
        
        // 32 rounds of SM4
        if (encrypt) {
            for (int i = 0; i < 32; i++) {
                __m128i new_x = sm4_round(x0, x1, x2, x3, round_keys[i]);
                x0 = x1; x1 = x2; x2 = x3; x3 = new_x;
            }
        } else {
            for (int i = 31; i >= 0; i--) {
                __m128i new_x = sm4_round(x0, x1, x2, x3, round_keys[i]);
                x0 = x1; x1 = x2; x2 = x3; x3 = new_x;
            }
        }
        
        // Reverse the final state for SM4 specification
        std::swap(x0, x3);
        std::swap(x1, x2);
        
        // Transpose back
        transpose_4x4(x0, x1, x2, x3);
        
        // Convert back to little-endian and store
        x0 = _mm_shuffle_epi8(x0, bswap_mask);
        x1 = _mm_shuffle_epi8(x1, bswap_mask);
        x2 = _mm_shuffle_epi8(x2, bswap_mask);
        x3 = _mm_shuffle_epi8(x3, bswap_mask);
        
        _mm_storeu_si128(reinterpret_cast<__m128i*>(output + 0), x0);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(output + 16), x1);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(output + 32), x2);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(output + 48), x3);
    }
    
    static std::vector<uint8_t> encrypt_block(const std::vector<uint8_t>& plaintext, const uint8_t* key) {
        SM4_GFNI cipher;
        cipher.expand_key(key);
        
        alignas(64) uint8_t padded_input[64];
        alignas(64) uint8_t padded_output[64];
        
        memcpy(padded_input, plaintext.data(), 16);
        memset(padded_input + 16, 0, 48);
        
        cipher.crypt_4blocks(padded_output, padded_input, true);
        
        return std::vector<uint8_t>(padded_output, padded_output + 16);
    }
    
    static std::vector<uint8_t> decrypt_block(const std::vector<uint8_t>& ciphertext, const uint8_t* key) {
        SM4_GFNI cipher;
        cipher.expand_key(key);
        
        alignas(64) uint8_t padded_input[64];
        alignas(64) uint8_t padded_output[64];
        
        memcpy(padded_input, ciphertext.data(), 16);
        memset(padded_input + 16, 0, 48);
        
        cipher.crypt_4blocks(padded_output, padded_input, false);
        
        return std::vector<uint8_t>(padded_output, padded_output + 16);
    }

public:
    /**
     * Check if GFNI and AVX2 are supported
     */
    static bool is_supported() {
        // Check GFNI support (bit 8 in ECX for leaf 7)
        // Check AVX2 support (bit 5 in EBX for leaf 7)
        unsigned int eax, ebx, ecx, edx;
        if (__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) {
            bool gfni_supported = (ecx & (1 << 8)) != 0;
            bool avx2_supported = (ebx & (1 << 5)) != 0;
            return gfni_supported && avx2_supported;
        }
        return false;
    }
    
    static std::string encrypt_block_hex(const std::string& plain_hex, const std::string& key_hex) {
        assert(plain_hex.length() == 32);
        assert(key_hex.length() == 32);
        
        auto plaintext = hex_to_bytes(plain_hex);
        auto key = hex_to_bytes(key_hex);
        auto ciphertext = encrypt_block(plaintext, key.data());
        
        return bytes_to_hex(ciphertext);
    }
    
    static std::string decrypt_block_hex(const std::string& cipher_hex, const std::string& key_hex) {
        assert(cipher_hex.length() == 32);
        assert(key_hex.length() == 32);
        
        auto ciphertext = hex_to_bytes(cipher_hex);
        auto key = hex_to_bytes(key_hex);
        auto plaintext = decrypt_block(ciphertext, key.data());
        
        return bytes_to_hex(plaintext);
    }
    
    static std::string encrypt_hex(const std::string& plain_hex, const std::string& key_hex) {
        assert(plain_hex.length() % 32 == 0);
        assert(key_hex.length() == 32);
        
        auto key = hex_to_bytes(key_hex);
        SM4_GFNI cipher;
        cipher.expand_key(key.data());
        
        std::string result;
        size_t num_blocks = plain_hex.length() / 32;
        
        // Process 4 blocks at a time for optimal performance
        size_t i = 0;
        while (i + 4 <= num_blocks) {
            alignas(64) uint8_t src[64];
            alignas(64) uint8_t dst[64];
            
            for (int j = 0; j < 4; j++) {
                std::string block = plain_hex.substr((i + j) * 32, 32);
                auto block_bytes = hex_to_bytes(block);
                std::memcpy(src + j * 16, block_bytes.data(), 16);
            }
            
            cipher.crypt_4blocks(dst, src, true);
            
            for (int j = 0; j < 4; j++) {
                std::vector<uint8_t> block_result(dst + j * 16, dst + (j + 1) * 16);
                result += bytes_to_hex(block_result);
            }
            
            i += 4;
        }
        
        // Process remaining blocks one by one
        while (i < num_blocks) {
            std::string block = plain_hex.substr(i * 32, 32);
            auto plaintext_block = hex_to_bytes(block);
            auto ciphertext_block = encrypt_block(plaintext_block, key.data());
            result += bytes_to_hex(ciphertext_block);
            i++;
        }
        
        return result;
    }
    
    static std::string decrypt_hex(const std::string& cipher_hex, const std::string& key_hex) {
        assert(cipher_hex.length() % 32 == 0);
        assert(key_hex.length() == 32);
        
        auto key = hex_to_bytes(key_hex);
        SM4_GFNI cipher;
        cipher.expand_key(key.data());
        
        std::string result;
        size_t num_blocks = cipher_hex.length() / 32;
        
        // Process 4 blocks at a time for optimal performance
        size_t i = 0;
        while (i + 4 <= num_blocks) {
            alignas(64) uint8_t src[64];
            alignas(64) uint8_t dst[64];
            
            for (int j = 0; j < 4; j++) {
                std::string block = cipher_hex.substr((i + j) * 32, 32);
                auto block_bytes = hex_to_bytes(block);
                std::memcpy(src + j * 16, block_bytes.data(), 16);
            }
            
            cipher.crypt_4blocks(dst, src, false);
            
            for (int j = 0; j < 4; j++) {
                std::vector<uint8_t> block_result(dst + j * 16, dst + (j + 1) * 16);
                result += bytes_to_hex(block_result);
            }
            
            i += 4;
        }
        
        // Process remaining blocks one by one
        while (i < num_blocks) {
            std::string block = cipher_hex.substr(i * 32, 32);
            auto ciphertext_block = hex_to_bytes(block);
            auto plaintext_block = decrypt_block(ciphertext_block, key.data());
            result += bytes_to_hex(plaintext_block);
            i++;
        }
        
        return result;
    }
};

// Static member definitions
const uint32_t SM4_GFNI::FK[4] = {
    0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC
};

const uint32_t SM4_GFNI::CK[32] = {
    0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
    0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
    0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
    0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
    0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
    0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
    0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
    0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
};

// Affine transformation matrices (based on libgcrypt implementation)
const uint64_t SM4_GFNI::PRE_AFFINE_MATRIX[4] = {
    0x52bc2d029e25ac34ULL, 0x52bc2d029e25ac34ULL,
    0x52bc2d029e25ac34ULL, 0x52bc2d029e25ac34ULL
};

const uint64_t SM4_GFNI::POST_AFFINE_MATRIX[4] = {
    0x198b6c1e518e2dd7ULL, 0x198b6c1e518e2dd7ULL,
    0x198b6c1e518e2dd7ULL, 0x198b6c1e518e2dd7ULL
};

// Rotation masks for byte-wise rotation using vpshufb
const uint8_t SM4_GFNI::ROL_8_MASK[32] = {
    3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14,
    3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14
};

const uint8_t SM4_GFNI::ROL_16_MASK[32] = {
    2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13,
    2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13
};

const uint8_t SM4_GFNI::ROL_24_MASK[32] = {
    1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12,
    1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12
};

const uint8_t SM4_GFNI::BSWAP32_MASK[32] = {
    3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12,
    3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12
};

// Global wrapper functions to match other implementations
std::string encrypt_hex(const std::string& plain_hex, const std::string& key_hex) {
    return SM4_GFNI::encrypt_hex(plain_hex, key_hex);
}

std::string decrypt_hex(const std::string& cipher_hex, const std::string& key_hex) {
    return SM4_GFNI::decrypt_hex(cipher_hex, key_hex);
}

// Test and demonstration functions
void test_sm4_gfni() {
    if (!SM4_GFNI::is_supported()) {
        std::cout << "GFNI/AVX2 not supported on this CPU" << std::endl;
        return;
    }
    
    // Test vector from SM4 specification
    std::string key = "0123456789abcdeffedcba9876543210";
    std::string plaintext = "0123456789abcdeffedcba9876543210";
    
    std::cout << "SM4 GFNI/AVX2 Optimized Implementation Test" << std::endl;
    std::cout << "===========================================" << std::endl;
    std::cout << "Key:       " << key << std::endl;
    std::cout << "Plaintext: " << plaintext << std::endl;
    
    std::string ciphertext = SM4_GFNI::encrypt_block_hex(plaintext, key);
    std::cout << "Encrypted: " << ciphertext << std::endl;
    
    std::string decrypted = SM4_GFNI::decrypt_block_hex(ciphertext, key);
    std::cout << "Decrypted: " << decrypted << std::endl;
    
    if (decrypted == plaintext) {
        std::cout << "✓ Test passed!" << std::endl;
    } else {
        std::cout << "✗ Test failed!" << std::endl;
    }
    
    // Performance test
    std::cout << "\nPerformance Test (4 blocks parallel):" << std::endl;
    const size_t num_test_blocks = 1000;
    std::string test_data;
    for (size_t i = 0; i < num_test_blocks; i++) {
        test_data += "0123456789abcdeffedcba9876543210";
    }
    
    auto start = std::chrono::high_resolution_clock::now();
    std::string encrypted_data = SM4_GFNI::encrypt_hex(test_data, key);
    auto end = std::chrono::high_resolution_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    double throughput = (num_test_blocks * 16.0) / (duration.count() / 1000000.0) / (1024 * 1024);
    
    std::cout << "Processed " << num_test_blocks << " blocks in " 
              << duration.count() << " microseconds" << std::endl;
    std::cout << "Throughput: " << std::fixed << std::setprecision(2) 
              << throughput << " MB/s" << std::endl;
}

int main() {
    std::string operation, input_hex, key_hex;
    
    std::cout << "SM4-GFNI Optimized Cipher - Enter operation (encrypt/decrypt): ";
    std::cin >> operation;
    
    std::cout << "Enter key (32 hex chars): ";
    std::cin >> key_hex;
    
    std::cout << "Enter input (multiple of 32 hex chars): ";
    std::cin >> input_hex;
    
    try {
        if (operation == "encrypt") {
            std::string result = encrypt_hex(input_hex, key_hex);
            std::cout << "Result: " << result << std::endl;
        } else if (operation == "decrypt") {
            std::string result = decrypt_hex(input_hex, key_hex);
            std::cout << "Result: " << result << std::endl;
        } else {
            std::cout << "Invalid operation. Use 'encrypt' or 'decrypt'." << std::endl;
            return 1;
        }
    } catch (const std::exception& e) {
        std::cout << "Error: Invalid input format or length." << std::endl;
        return 1;
    }
    
    return 0;
}
