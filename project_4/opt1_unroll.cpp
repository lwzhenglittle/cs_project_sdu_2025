

#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <cstdint>

class SM3_Unrolled {
private:
    static const uint32_t IV[8];
    
    uint32_t H[8];
    
    std::vector<uint8_t> buffer;
    uint64_t total_length;
    
    static inline uint32_t rotl(uint32_t x, int n) {
        return (x << n) | (x >> (32 - n));
    }
    
    static inline uint32_t FF_0_15(uint32_t x, uint32_t y, uint32_t z) {
        return x ^ y ^ z;
    }
    
    static inline uint32_t FF_16_63(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) | (x & z) | (y & z);
    }
    
    static inline uint32_t GG_0_15(uint32_t x, uint32_t y, uint32_t z) {
        return x ^ y ^ z;
    }
    
    static inline uint32_t GG_16_63(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) | (~x & z);
    }
    
    static inline uint32_t P0(uint32_t x) {
        return x ^ rotl(x, 9) ^ rotl(x, 17);
    }
    
    static inline uint32_t P1(uint32_t x) {
        return x ^ rotl(x, 15) ^ rotl(x, 23);
    }
    
    static inline uint32_t Tj(int j) {
        if (j >= 0 && j <= 15) {
            return 0x79cc4519;
        } else if (j >= 16 && j <= 63) {
            return 0x7a879d8a;
        }
        return 0;
    }
    
    #define ROUND(j, FF_func, GG_func) do { \
        uint32_t SS1 = rotl((rotl(A, 12) + E + rotl(Tj(j), (j) % 32)), 7); \
        uint32_t SS2 = SS1 ^ rotl(A, 12); \
        uint32_t TT1 = FF_func(A, B, C) + D + SS2 + W_prime[j]; \
        uint32_t TT2 = GG_func(E, F, G) + H_var + SS1 + W[j]; \
        D = C; \
        C = rotl(B, 9); \
        B = A; \
        A = TT1; \
        H_var = G; \
        G = rotl(F, 19); \
        F = E; \
        E = P0(TT2); \
    } while(0)
    
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
        
        for (int j = 0; j < 64; j++) {
            W_prime[j] = W[j] ^ W[j + 4];
        }
        
        uint32_t A = H[0], B = H[1], C = H[2], D = H[3];
        uint32_t E = H[4], F = H[5], G = H[6], H_var = H[7];
        
        ROUND(0, FF_0_15, GG_0_15); ROUND(1, FF_0_15, GG_0_15);
        ROUND(2, FF_0_15, GG_0_15); ROUND(3, FF_0_15, GG_0_15);
        ROUND(4, FF_0_15, GG_0_15); ROUND(5, FF_0_15, GG_0_15);
        ROUND(6, FF_0_15, GG_0_15); ROUND(7, FF_0_15, GG_0_15);
        ROUND(8, FF_0_15, GG_0_15); ROUND(9, FF_0_15, GG_0_15);
        ROUND(10, FF_0_15, GG_0_15); ROUND(11, FF_0_15, GG_0_15);
        ROUND(12, FF_0_15, GG_0_15); ROUND(13, FF_0_15, GG_0_15);
        ROUND(14, FF_0_15, GG_0_15); ROUND(15, FF_0_15, GG_0_15);
        
        ROUND(16, FF_16_63, GG_16_63); ROUND(17, FF_16_63, GG_16_63);
        ROUND(18, FF_16_63, GG_16_63); ROUND(19, FF_16_63, GG_16_63);
        ROUND(20, FF_16_63, GG_16_63); ROUND(21, FF_16_63, GG_16_63);
        ROUND(22, FF_16_63, GG_16_63); ROUND(23, FF_16_63, GG_16_63);
        ROUND(24, FF_16_63, GG_16_63); ROUND(25, FF_16_63, GG_16_63);
        ROUND(26, FF_16_63, GG_16_63); ROUND(27, FF_16_63, GG_16_63);
        ROUND(28, FF_16_63, GG_16_63); ROUND(29, FF_16_63, GG_16_63);
        ROUND(30, FF_16_63, GG_16_63); ROUND(31, FF_16_63, GG_16_63);
        ROUND(32, FF_16_63, GG_16_63); ROUND(33, FF_16_63, GG_16_63);
        ROUND(34, FF_16_63, GG_16_63); ROUND(35, FF_16_63, GG_16_63);
        ROUND(36, FF_16_63, GG_16_63); ROUND(37, FF_16_63, GG_16_63);
        ROUND(38, FF_16_63, GG_16_63); ROUND(39, FF_16_63, GG_16_63);
        ROUND(40, FF_16_63, GG_16_63); ROUND(41, FF_16_63, GG_16_63);
        ROUND(42, FF_16_63, GG_16_63); ROUND(43, FF_16_63, GG_16_63);
        ROUND(44, FF_16_63, GG_16_63); ROUND(45, FF_16_63, GG_16_63);
        ROUND(46, FF_16_63, GG_16_63); ROUND(47, FF_16_63, GG_16_63);
        ROUND(48, FF_16_63, GG_16_63); ROUND(49, FF_16_63, GG_16_63);
        ROUND(50, FF_16_63, GG_16_63); ROUND(51, FF_16_63, GG_16_63);
        ROUND(52, FF_16_63, GG_16_63); ROUND(53, FF_16_63, GG_16_63);
        ROUND(54, FF_16_63, GG_16_63); ROUND(55, FF_16_63, GG_16_63);
        ROUND(56, FF_16_63, GG_16_63); ROUND(57, FF_16_63, GG_16_63);
        ROUND(58, FF_16_63, GG_16_63); ROUND(59, FF_16_63, GG_16_63);
        ROUND(60, FF_16_63, GG_16_63); ROUND(61, FF_16_63, GG_16_63);
        ROUND(62, FF_16_63, GG_16_63); ROUND(63, FF_16_63, GG_16_63);
        
        H[0] ^= A; H[1] ^= B; H[2] ^= C; H[3] ^= D;
        H[4] ^= E; H[5] ^= F; H[6] ^= G; H[7] ^= H_var;
    }
    
    #undef ROUND
    
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
    SM3_Unrolled() {
        reset();
    }
    
    void reset() {
        for (int i = 0; i < 8; i++) {
            H[i] = IV[i];
        }
        buffer.clear();
        total_length = 0;
    }
    
    void update(const uint8_t* data, size_t length) {
        total_length += length;
        
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
};

const uint32_t SM3_Unrolled::IV[8] = {
    0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
    0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
};

int main() {
    SM3_Unrolled sm3;
    
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
