

#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <cstdint>

class SM3_OnTheFly {
private:
    static const uint32_t IV[8];
    
    uint32_t H[8];
    
    std::vector<uint8_t> buffer;
    uint64_t total_length;
    
    static inline uint32_t rotl(uint32_t x, int n) {
        return (x << n) | (x >> (32 - n));
    }
    
    static inline uint32_t FF(uint32_t x, uint32_t y, uint32_t z, int j) {
        if (j <= 15) {
            return x ^ y ^ z;
        } else {
            return (x & y) | (x & z) | (y & z);
        }
    }
    
    static inline uint32_t GG(uint32_t x, uint32_t y, uint32_t z, int j) {
        if (j <= 15) {
            return x ^ y ^ z;
        } else {
            return (x & y) | (~x & z);
        }
    }
    
    static inline uint32_t P0(uint32_t x) {
        return x ^ rotl(x, 9) ^ rotl(x, 17);
    }
    
    static inline uint32_t P1(uint32_t x) {
        return x ^ rotl(x, 15) ^ rotl(x, 23);
    }
    
    static inline uint32_t Tj(int j) {
        return (j <= 15) ? 0x79cc4519 : 0x7a879d8a;
    }
    
    uint32_t computeW(int j, const uint32_t* W_base, uint32_t* W_cache) {
        if (j < 16) {
            return W_base[j];
        }
        
        if (W_cache[j] != 0xFFFFFFFF) {
            return W_cache[j];
        }
        
        uint32_t w_j_minus_16 = computeW(j - 16, W_base, W_cache);
        uint32_t w_j_minus_9 = computeW(j - 9, W_base, W_cache);
        uint32_t w_j_minus_3 = computeW(j - 3, W_base, W_cache);
        uint32_t w_j_minus_13 = computeW(j - 13, W_base, W_cache);
        uint32_t w_j_minus_6 = computeW(j - 6, W_base, W_cache);
        
        uint32_t result = P1(w_j_minus_16 ^ w_j_minus_9 ^ rotl(w_j_minus_3, 15)) ^ 
                         rotl(w_j_minus_13, 7) ^ w_j_minus_6;
        
        W_cache[j] = result;
        return result;
    }
    
    void processBlock(const uint8_t* block) {
        uint32_t W_base[16];
        uint32_t W_cache[68];
        
        for (int i = 0; i < 68; i++) {
            W_cache[i] = 0xFFFFFFFF;
        }
        
        for (int i = 0; i < 16; i++) {
            W_base[i] = (static_cast<uint32_t>(block[i * 4]) << 24) |
                        (static_cast<uint32_t>(block[i * 4 + 1]) << 16) |
                        (static_cast<uint32_t>(block[i * 4 + 2]) << 8) |
                        (static_cast<uint32_t>(block[i * 4 + 3]));
            W_cache[i] = W_base[i];
        }
        
        uint32_t A = H[0], B = H[1], C = H[2], D = H[3];
        uint32_t E = H[4], F = H[5], G = H[6], H_var = H[7];
        
        for (int j = 0; j < 64; j++) {
            uint32_t W_j = computeW(j, W_base, W_cache);
            uint32_t W_j_plus_4 = computeW(j + 4, W_base, W_cache);
            uint32_t W_prime_j = W_j ^ W_j_plus_4;
            
            uint32_t SS1 = rotl((rotl(A, 12) + E + rotl(Tj(j), j % 32)), 7);
            uint32_t SS2 = SS1 ^ rotl(A, 12);
            uint32_t TT1 = FF(A, B, C, j) + D + SS2 + W_prime_j;
            uint32_t TT2 = GG(E, F, G, j) + H_var + SS1 + W_j;
            
            D = C;
            C = rotl(B, 9);
            B = A;
            A = TT1;
            H_var = G;
            G = rotl(F, 19);
            F = E;
            E = P0(TT2);
            
            if (j >= 16) {
                if (j - 16 < 52) { 
                } else {
                    W_cache[j - 16] = 0xFFFFFFFF;
                }
            }
        }
        
        H[0] ^= A;
        H[1] ^= B;
        H[2] ^= C;
        H[3] ^= D;
        H[4] ^= E;
        H[5] ^= F;
        H[6] ^= G;
        H[7] ^= H_var;
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
    SM3_OnTheFly() {
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

const uint32_t SM3_OnTheFly::IV[8] = {
    0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
    0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
};

int main() {
    SM3_OnTheFly sm3;
    
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
