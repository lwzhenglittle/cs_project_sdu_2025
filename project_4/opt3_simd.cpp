

#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <cstdint>
#include <immintrin.h>  // For SIMD intrinsics

class SM3 {
private:
    static const uint32_t IV[8];
    
    alignas(16) uint32_t H[8];  
    
    std::vector<uint8_t> buffer;
    uint64_t total_length;
    
    static uint32_t rotl(uint32_t x, int n) {
        return (x << n) | (x >> (32 - n));
    }
    
    static uint32_t FF(uint32_t x, uint32_t y, uint32_t z, int j) {
        if (j >= 0 && j <= 15) {
            return x ^ y ^ z;
        } else if (j >= 16 && j <= 63) {
            return (x & y) | (x & z) | (y & z);
        }
        return 0;
    }
    
    static uint32_t GG(uint32_t x, uint32_t y, uint32_t z, int j) {
        if (j >= 0 && j <= 15) {
            return x ^ y ^ z;
        } else if (j >= 16 && j <= 63) {
            return (x & y) | (~x & z);
        }
        return 0;
    }
    
    static uint32_t P0(uint32_t x) {
        return x ^ rotl(x, 9) ^ rotl(x, 17);
    }
    
    static uint32_t P1(uint32_t x) {
        return x ^ rotl(x, 15) ^ rotl(x, 23);
    }
    
    static void xor_arrays_simd(uint32_t* dest, const uint32_t* src1, const uint32_t* src2, int count) {
        int simd_count = (count / 4) * 4;  
        
        for (int i = 0; i < simd_count; i += 4) {
            __m128i a = _mm_loadu_si128(reinterpret_cast<const __m128i*>(src1 + i));
            __m128i b = _mm_loadu_si128(reinterpret_cast<const __m128i*>(src2 + i));
            __m128i result = _mm_xor_si128(a, b);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(dest + i), result);
        }
        
        for (int i = simd_count; i < count; i++) {
            dest[i] = src1[i] ^ src2[i];
        }
    }
    
    static uint32_t Tj(int j) {
        if (j >= 0 && j <= 15) {
            return 0x79cc4519;
        } else if (j >= 16 && j <= 63) {
            return 0x7a879d8a;
        }
        return 0;
    }
    
    void processBlock(const uint8_t* block) {
        uint32_t W[68];
        uint32_t W_prime[64];
        
        for (int i = 0; i < 16; i++) {
            W[i] = (static_cast<uint32_t>(block[i * 4]) << 24) |
                   (static_cast<uint32_t>(block[i * 4 + 1]) << 16) |
                   (static_cast<uint32_t>(block[i * 4 + 2]) << 8) |
                   (static_cast<uint32_t>(block[i * 4 + 3]));
        }
        
        for (int j = 16; j < 68; j++) {
            W[j] = P1(W[j-16] ^ W[j-9] ^ rotl(W[j-3], 15)) ^ rotl(W[j-13], 7) ^ W[j-6];
        }
        
        xor_arrays_simd(W_prime, W, W + 4, 64);
        
        uint32_t A = H[0], B = H[1], C = H[2], D = H[3];
        uint32_t E = H[4], F = H[5], G = H[6], H_var = H[7];
        
        for (int j = 0; j < 64; j++) {
            uint32_t SS1 = rotl((rotl(A, 12) + E + rotl(Tj(j), j % 32)), 7);
            uint32_t SS2 = SS1 ^ rotl(A, 12);
            uint32_t TT1 = FF(A, B, C, j) + D + SS2 + W_prime[j];
            uint32_t TT2 = GG(E, F, G, j) + H_var + SS1 + W[j];
            
            D = C;
            C = rotl(B, 9);
            B = A;
            A = TT1;
            H_var = G;
            G = rotl(F, 19);
            F = E;
            E = P0(TT2);
            
            A = A;
            B = B;
            C = C;
            D = D;
            E = E;
            F = F;
            G = G;
            // H_var is already updated above
        }
        
        __m128i hash_low = _mm_load_si128(reinterpret_cast<const __m128i*>(H));
        __m128i hash_high = _mm_load_si128(reinterpret_cast<const __m128i*>(H + 4));
        __m128i working_low = _mm_set_epi32(D, C, B, A);
        __m128i working_high = _mm_set_epi32(H_var, G, F, E);
        
        hash_low = _mm_xor_si128(hash_low, working_low);
        hash_high = _mm_xor_si128(hash_high, working_high);
        
        _mm_store_si128(reinterpret_cast<__m128i*>(H), hash_low);
        _mm_store_si128(reinterpret_cast<__m128i*>(H + 4), hash_high);
    }
    
    void padMessage() {
        uint64_t bit_length = total_length * 8;
        
        buffer.push_back(0x80);
        
        while ((buffer.size() % 64) != 56) {
            buffer.push_back(0x00);
        }
        
        for (int i = 7; i >= 0; i--) {
            buffer.push_back(static_cast<uint8_t>((bit_length >> (i * 8)) & 0xFF));
        }
    }
    
public:
    SM3() {
        reset();
    }
    
    void reset() {
        __m128i iv_low = _mm_loadu_si128(reinterpret_cast<const __m128i*>(IV));
        __m128i iv_high = _mm_loadu_si128(reinterpret_cast<const __m128i*>(IV + 4));
        _mm_store_si128(reinterpret_cast<__m128i*>(H), iv_low);
        _mm_store_si128(reinterpret_cast<__m128i*>(H + 4), iv_high);
        
        buffer.clear();
        total_length = 0;
    }
    
    void update(const uint8_t* data, size_t length) {
        total_length += length;
        
        buffer.reserve(buffer.size() + length);
        
        for (size_t i = 0; i < length; i++) {
            buffer.push_back(data[i]);
        }
        
        while (buffer.size() >= 64) {
            processBlock(buffer.data());
            buffer.erase(buffer.begin(), buffer.begin() + 64);
        }
    }
    
    std::string finalize() {
        padMessage();
        
        for (size_t i = 0; i < buffer.size(); i += 64) {
            processBlock(buffer.data() + i);
        }
        
        std::stringstream ss;
        for (int i = 0; i < 8; i++) {
            ss << std::hex << std::setfill('0') << std::setw(8) << H[i];
        }
        
        return ss.str();
    }
    
    static std::string hash(const std::vector<uint8_t>& message) {
        SM3 sm3;
        sm3.update(message.data(), message.size());
        return sm3.finalize();
    }
};

const uint32_t SM3::IV[8] = {
    0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
    0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
};

int main() {
    SM3 sm3;
    
    std::vector<uint8_t> input_data;
    int byte;
    
    while ((byte = std::cin.get()) != EOF) {
        input_data.push_back(static_cast<uint8_t>(byte));
    }
    
    sm3.update(input_data.data(), input_data.size());
    std::string hash_result = sm3.finalize();
    
    std::cout << hash_result << std::endl;
    
    return 0;
}
