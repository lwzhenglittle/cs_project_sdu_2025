#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <immintrin.h>
#include <wmmintrin.h>

const uint8_t SM4_TO_AES_TRANSFORM[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

const uint8_t AES_TO_SM4_TRANSFORM[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

class SM4_AESNI {
private:
    static const uint32_t FK[4];
    static const uint32_t CK[32];
    
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
    
    static std::vector<uint8_t> uint32_to_bytes(uint32_t value) {
        return {
            static_cast<uint8_t>((value >> 24) & 0xFF),
            static_cast<uint8_t>((value >> 16) & 0xFF),
            static_cast<uint8_t>((value >> 8) & 0xFF),
            static_cast<uint8_t>(value & 0xFF)
        };
    }
    
    static uint32_t bytes_to_uint32(const std::vector<uint8_t>& bytes, size_t offset) {
        return (static_cast<uint32_t>(bytes[offset]) << 24) |
               (static_cast<uint32_t>(bytes[offset + 1]) << 16) |
               (static_cast<uint32_t>(bytes[offset + 2]) << 8) |
               static_cast<uint32_t>(bytes[offset + 3]);
    }
    
    static uint32_t left_rotate(uint32_t value, int bits) {
        return (value << bits) | (value >> (32 - bits));
    }
    
    static __m128i sm4_sbox_4x_aesni(__m128i x) {
        const __m128i c0f __attribute__((aligned(0x10))) =
            { 0x0F0F0F0F0F0F0F0F, 0x0F0F0F0F0F0F0F0F };
            
        const __m128i shr __attribute__((aligned(0x10))) =
            { 0x0B0E0104070A0D00, 0x0306090C0F020508 };

        const __m128i m1l = _mm_set_epi64x(0xC7C1B4B222245157LL, 0x9197E2E474720701LL);
        const __m128i m1h = _mm_set_epi64x(0xF052B91BF95BB012LL, 0xE240AB09EB49A200LL);

        const __m128i m2l = _mm_set_epi64x(0xEDD14478172BBE82LL, 0x5B67F2CEA19D0834LL);
        const __m128i m2h = _mm_set_epi64x(0x11CDBE62CC1063BFLL, 0xAE7201DD73AFDC00LL);

        __m128i y;

        y = _mm_and_si128(x, c0f);
        y = _mm_shuffle_epi8(m1l, y);
        x = _mm_srli_epi64(x, 4);
        x = _mm_and_si128(x, c0f);
        x = _mm_shuffle_epi8(m1h, x) ^ y;

        x = _mm_shuffle_epi8(x, shr);
        
        x = _mm_aesenclast_si128(x, c0f);

        y = _mm_andnot_si128(x, c0f);
        y = _mm_shuffle_epi8(m2l, y);
        x = _mm_srli_epi64(x, 4);
        x = _mm_and_si128(x, c0f);
        x = _mm_shuffle_epi8(m2h, x) ^ y;

        return x;
    }
    
    static uint32_t tau_aesni(uint32_t A) {
        alignas(16) uint8_t input_bytes[16] = {0};
        alignas(16) uint8_t output_bytes[16];
        
        input_bytes[0] = (A >> 24) & 0xFF;
        input_bytes[1] = (A >> 16) & 0xFF;
        input_bytes[2] = (A >> 8) & 0xFF;
        input_bytes[3] = A & 0xFF;
        
        __m128i input_vec = _mm_load_si128((__m128i*)input_bytes);
        
        __m128i result_vec = sm4_sbox_4x_aesni(input_vec);
        
        _mm_store_si128((__m128i*)output_bytes, result_vec);
        
        return (static_cast<uint32_t>(output_bytes[0]) << 24) |
               (static_cast<uint32_t>(output_bytes[1]) << 16) |
               (static_cast<uint32_t>(output_bytes[2]) << 8) |
               static_cast<uint32_t>(output_bytes[3]);
    }
    
    static void tau_aesni_4x(uint32_t input[4], uint32_t output[4]) {
        alignas(16) uint8_t input_bytes[16];
        alignas(16) uint8_t output_bytes[16];
        
        for (int i = 0; i < 4; i++) {
            input_bytes[i*4 + 0] = (input[i] >> 24) & 0xFF;
            input_bytes[i*4 + 1] = (input[i] >> 16) & 0xFF;
            input_bytes[i*4 + 2] = (input[i] >> 8) & 0xFF;
            input_bytes[i*4 + 3] = input[i] & 0xFF;
        }
        
        __m128i input_vec = _mm_load_si128((__m128i*)input_bytes);
        __m128i result_vec = sm4_sbox_4x_aesni(input_vec);
        _mm_store_si128((__m128i*)output_bytes, result_vec);
        
        for (int i = 0; i < 4; i++) {
            output[i] = (static_cast<uint32_t>(output_bytes[i*4 + 0]) << 24) |
                       (static_cast<uint32_t>(output_bytes[i*4 + 1]) << 16) |
                       (static_cast<uint32_t>(output_bytes[i*4 + 2]) << 8) |
                       static_cast<uint32_t>(output_bytes[i*4 + 3]);
        }
    }
    
    static uint32_t L(uint32_t B) {
        return B ^ left_rotate(B, 2) ^ left_rotate(B, 10) ^ left_rotate(B, 18) ^ left_rotate(B, 24);
    }
    
    static uint32_t L_prime(uint32_t B) {
        return B ^ left_rotate(B, 13) ^ left_rotate(B, 23);
    }
    
    static uint32_t T(uint32_t X) {
        return L(tau_aesni(X));
    }
    
    static uint32_t T_prime(uint32_t X) {
        return L_prime(tau_aesni(X));
    }
    
    static std::vector<uint32_t> key_schedule(const std::vector<uint8_t>& key) {
        uint32_t MK[4];
        for (int i = 0; i < 4; i++) {
            MK[i] = bytes_to_uint32(key, i * 4);
        }
        
        uint32_t K[36];
        for (int i = 0; i < 4; i++) {
            K[i] = MK[i] ^ FK[i];
        }
        
        std::vector<uint32_t> round_keys(32);
        
        for (int i = 0; i < 32; i++) {
            K[i + 4] = K[i] ^ T_prime(K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ CK[i]);
            round_keys[i] = K[i + 4];
        }
        
        return round_keys;
    }
    
    static void encrypt_4blocks_aesni(const uint32_t rk[32], const uint8_t src[64], uint8_t dst[64]) {
        const __m128i c0f __attribute__((aligned(0x10))) =
            { 0x0F0F0F0F0F0F0F0F, 0x0F0F0F0F0F0F0F0F };
            
        const __m128i flp __attribute__((aligned(0x10))) =
            { 0x0405060700010203, 0x0C0D0E0F08090A0B };
            
        const __m128i shr __attribute__((aligned(0x10))) =
            { 0x0B0E0104070A0D00, 0x0306090C0F020508 };

        const __m128i m1l = _mm_set_epi64x(0xC7C1B4B222245157LL, 0x9197E2E474720701LL);
        const __m128i m1h = _mm_set_epi64x(0xF052B91BF95BB012LL, 0xE240AB09EB49A200LL);
        const __m128i m2l = _mm_set_epi64x(0xEDD14478172BBE82LL, 0x5B67F2CEA19D0834LL);
        const __m128i m2h = _mm_set_epi64x(0x11CDBE62CC1063BFLL, 0xAE7201DD73AFDC00LL);

        const __m128i r08 __attribute__((aligned(0x10))) =
            { 0x0605040702010003, 0x0E0D0C0F0A09080B };
        const __m128i r16 __attribute__((aligned(0x10))) =
            { 0x0504070601000302, 0x0D0C0F0E09080B0A };
        const __m128i r24 __attribute__((aligned(0x10))) =
            { 0x0407060500030201, 0x0C0F0E0D080B0A09 };

        __m128i x, y, t0, t1, t2, t3;
        uint32_t k;
        const uint32_t *p32 = (const uint32_t*)src;
        uint32_t *dst32 = (uint32_t*)dst;
        alignas(16) uint32_t v[4];

        t0 = _mm_set_epi32(p32[12], p32[ 8], p32[ 4], p32[ 0]);
        t0 = _mm_shuffle_epi8(t0, flp);
        t1 = _mm_set_epi32(p32[13], p32[ 9], p32[ 5], p32[ 1]);
        t1 = _mm_shuffle_epi8(t1, flp);
        t2 = _mm_set_epi32(p32[14], p32[10], p32[ 6], p32[ 2]);
        t2 = _mm_shuffle_epi8(t2, flp);
        t3 = _mm_set_epi32(p32[15], p32[11], p32[ 7], p32[ 3]);
        t3 = _mm_shuffle_epi8(t3, flp);

        for (int i = 0; i < 32; i++) {
            k = rk[i];
            x = t1 ^ t2 ^ t3 ^ _mm_set_epi32(k, k, k, k);

            y = _mm_and_si128(x, c0f);
            y = _mm_shuffle_epi8(m1l, y);
            x = _mm_srli_epi64(x, 4);
            x = _mm_and_si128(x, c0f);
            x = _mm_shuffle_epi8(m1h, x) ^ y;

            x = _mm_shuffle_epi8(x, shr);
            
            x = _mm_aesenclast_si128(x, c0f);

            y = _mm_andnot_si128(x, c0f);
            y = _mm_shuffle_epi8(m2l, y);
            x = _mm_srli_epi64(x, 4);
            x = _mm_and_si128(x, c0f);
            x = _mm_shuffle_epi8(m2h, x) ^ y;

            y = x ^ _mm_shuffle_epi8(x, r08) ^ _mm_shuffle_epi8(x, r16);
            y = _mm_slli_epi32(y, 2) ^ _mm_srli_epi32(y, 30);
            x = x ^ y ^ _mm_shuffle_epi8(x, r24);

            x ^= t0;
            t0 = t1;
            t1 = t2;
            t2 = t3;
            t3 = x;
        }

        _mm_store_si128((__m128i*)v, _mm_shuffle_epi8(t3, flp));
        dst32[ 0] = v[0]; dst32[ 4] = v[1]; dst32[ 8] = v[2]; dst32[12] = v[3];

        _mm_store_si128((__m128i*)v, _mm_shuffle_epi8(t2, flp));
        dst32[ 1] = v[0]; dst32[ 5] = v[1]; dst32[ 9] = v[2]; dst32[13] = v[3];

        _mm_store_si128((__m128i*)v, _mm_shuffle_epi8(t1, flp));
        dst32[ 2] = v[0]; dst32[ 6] = v[1]; dst32[10] = v[2]; dst32[14] = v[3];

        _mm_store_si128((__m128i*)v, _mm_shuffle_epi8(t0, flp));
        dst32[ 3] = v[0]; dst32[ 7] = v[1]; dst32[11] = v[2]; dst32[15] = v[3];
    }
    static std::vector<uint8_t> encrypt_block(const std::vector<uint8_t>& plaintext, 
                                             const std::vector<uint32_t>& round_keys) {
        std::vector<uint8_t> ciphertext(16);
        
        alignas(16) uint8_t src[64];
        alignas(16) uint8_t dst[64];
        
        for (int i = 0; i < 4; i++) {
            std::memcpy(src + i * 16, plaintext.data(), 16);
        }
        
        encrypt_4blocks_aesni(round_keys.data(), src, dst);
        
        std::memcpy(ciphertext.data(), dst, 16);
        
        return ciphertext;
    }
    
    static std::vector<uint8_t> decrypt_block(const std::vector<uint8_t>& ciphertext, 
                                             const std::vector<uint32_t>& round_keys) {
        std::vector<uint32_t> reverse_keys(round_keys.rbegin(), round_keys.rend());
        return encrypt_block(ciphertext, reverse_keys);
    }

public:
    static std::string encrypt_block_hex(const std::string& plain_hex, const std::string& key_hex) {
        assert(plain_hex.length() == 32);
        assert(key_hex.length() == 32);
        
        auto plaintext = hex_to_bytes(plain_hex);
        auto key = hex_to_bytes(key_hex);
        auto round_keys = key_schedule(key);
        auto ciphertext = encrypt_block(plaintext, round_keys);
        
        return bytes_to_hex(ciphertext);
    }
    
    static std::string decrypt_block_hex(const std::string& cipher_hex, const std::string& key_hex) {
        assert(cipher_hex.length() == 32);
        assert(key_hex.length() == 32);
        
        auto ciphertext = hex_to_bytes(cipher_hex);
        auto key = hex_to_bytes(key_hex);
        auto round_keys = key_schedule(key);
        auto plaintext = decrypt_block(ciphertext, round_keys);
        
        return bytes_to_hex(plaintext);
    }
    
    static std::string encrypt_hex(const std::string& plain_hex, const std::string& key_hex) {
        assert(plain_hex.length() % 32 == 0);
        assert(key_hex.length() == 32);
        
        auto key = hex_to_bytes(key_hex);
        auto round_keys = key_schedule(key);
        
        std::string result;
        size_t num_blocks = plain_hex.length() / 32;
        
        size_t i = 0;
        while (i + 4 <= num_blocks) {
            alignas(16) uint8_t src[64];
            alignas(16) uint8_t dst[64];
            
            for (int j = 0; j < 4; j++) {
                std::string block = plain_hex.substr((i + j) * 32, 32);
                auto block_bytes = hex_to_bytes(block);
                std::memcpy(src + j * 16, block_bytes.data(), 16);
            }
            
            encrypt_4blocks_aesni(round_keys.data(), src, dst);
            
            for (int j = 0; j < 4; j++) {
                std::vector<uint8_t> block_result(dst + j * 16, dst + (j + 1) * 16);
                result += bytes_to_hex(block_result);
            }
            
            i += 4;
        }
        
        while (i < num_blocks) {
            std::string block = plain_hex.substr(i * 32, 32);
            auto plaintext_block = hex_to_bytes(block);
            auto ciphertext_block = encrypt_block(plaintext_block, round_keys);
            result += bytes_to_hex(ciphertext_block);
            i++;
        }
        
        return result;
    }
    
    static std::string decrypt_hex(const std::string& cipher_hex, const std::string& key_hex) {
        assert(cipher_hex.length() % 32 == 0);
        assert(key_hex.length() == 32);
        
        auto key = hex_to_bytes(key_hex);
        auto round_keys = key_schedule(key);
        
        std::string result;
        for (size_t i = 0; i < cipher_hex.length(); i += 32) {
            std::string block = cipher_hex.substr(i, 32);
            auto ciphertext_block = hex_to_bytes(block);
            auto plaintext_block = decrypt_block(ciphertext_block, round_keys);
            result += bytes_to_hex(plaintext_block);
        }
        
        return result;
    }
};

const uint32_t SM4_AESNI::FK[4] = {
    0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc
};

const uint32_t SM4_AESNI::CK[32] = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
};

std::string encrypt_block_hex(const std::string &plain_hex, const std::string &key_hex) {
    return SM4_AESNI::encrypt_block_hex(plain_hex, key_hex);
}

std::string decrypt_block_hex(const std::string &cipher_hex, const std::string &key_hex) {
    return SM4_AESNI::decrypt_block_hex(cipher_hex, key_hex);
}

std::string encrypt_hex(const std::string &plain_hex, const std::string &key_hex) {
    return SM4_AESNI::encrypt_hex(plain_hex, key_hex);
}

std::string decrypt_hex(const std::string &cipher_hex, const std::string &key_hex) {
    return SM4_AESNI::decrypt_hex(cipher_hex, key_hex);
}

int main() {
    std::string operation, input_hex, key_hex;
    
    std::cout << "SM4-AESNI Optimized Cipher - Enter operation (encrypt/decrypt): ";
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
