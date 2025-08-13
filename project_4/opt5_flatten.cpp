

#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <cstdint>

class SM3_Flatten {
private:
    static const uint32_t IV[8];
    
    uint32_t H[8];
    
    std::vector<uint8_t> buffer;
    uint64_t total_length;
    
    #define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
    
    #define FF_0_15(x, y, z) ((x) ^ (y) ^ (z))
    #define FF_16_63(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
    
    #define GG_0_15(x, y, z) ((x) ^ (y) ^ (z))
    #define GG_16_63(x, y, z) (((x) & (y)) | ((~(x)) & (z)))
    
    #define P0(x) ((x) ^ ROTL((x), 9) ^ ROTL((x), 17))
    #define P1(x) ((x) ^ ROTL((x), 15) ^ ROTL((x), 23))
    
    #define TJ_0_15 0x79cc4519U
    #define TJ_16_63 0x7a879d8aU
    
    #define ROUND_0_15(j, A, B, C, D, E, F, G, H_var, W_j, W_prime_j) do { \
        uint32_t rot_A_12 = ROTL(A, 12); \
        uint32_t SS1 = ROTL((rot_A_12 + E + ROTL(TJ_0_15, (j) % 32)), 7); \
        uint32_t SS2 = SS1 ^ rot_A_12; \
        uint32_t TT1 = FF_0_15(A, B, C) + D + SS2 + (W_prime_j); \
        uint32_t TT2 = GG_0_15(E, F, G) + H_var + SS1 + (W_j); \
        \
        D = C; \
        C = ROTL(B, 9); \
        B = A; \
        A = TT1; \
        H_var = G; \
        G = ROTL(F, 19); \
        F = E; \
        E = P0(TT2); \
    } while(0)
    
    #define ROUND_16_63(j, A, B, C, D, E, F, G, H_var, W_j, W_prime_j) do { \
        uint32_t rot_A_12 = ROTL(A, 12); \
        uint32_t SS1 = ROTL((rot_A_12 + E + ROTL(TJ_16_63, (j) % 32)), 7); \
        uint32_t SS2 = SS1 ^ rot_A_12; \
        uint32_t TT1 = FF_16_63(A, B, C) + D + SS2 + (W_prime_j); \
        uint32_t TT2 = GG_16_63(E, F, G) + H_var + SS1 + (W_j); \
        \
        D = C; \
        C = ROTL(B, 9); \
        B = A; \
        A = TT1; \
        H_var = G; \
        G = ROTL(F, 19); \
        F = E; \
        E = P0(TT2); \
    } while(0)
    
    #define EXPAND_W(j, W) do { \
        W[j] = P1(W[(j)-16] ^ W[(j)-9] ^ ROTL(W[(j)-3], 15)) ^ ROTL(W[(j)-13], 7) ^ W[(j)-6]; \
    } while(0)
    
    void processBlock(const uint8_t* block) {
        uint32_t W[68] __attribute__((aligned(32)));
        uint32_t W_prime[64] __attribute__((aligned(32)));
        
        W[0] = (static_cast<uint32_t>(block[0]) << 24) | (static_cast<uint32_t>(block[1]) << 16) |
               (static_cast<uint32_t>(block[2]) << 8) | static_cast<uint32_t>(block[3]);
        W[1] = (static_cast<uint32_t>(block[4]) << 24) | (static_cast<uint32_t>(block[5]) << 16) |
               (static_cast<uint32_t>(block[6]) << 8) | static_cast<uint32_t>(block[7]);
        W[2] = (static_cast<uint32_t>(block[8]) << 24) | (static_cast<uint32_t>(block[9]) << 16) |
               (static_cast<uint32_t>(block[10]) << 8) | static_cast<uint32_t>(block[11]);
        W[3] = (static_cast<uint32_t>(block[12]) << 24) | (static_cast<uint32_t>(block[13]) << 16) |
               (static_cast<uint32_t>(block[14]) << 8) | static_cast<uint32_t>(block[15]);
        W[4] = (static_cast<uint32_t>(block[16]) << 24) | (static_cast<uint32_t>(block[17]) << 16) |
               (static_cast<uint32_t>(block[18]) << 8) | static_cast<uint32_t>(block[19]);
        W[5] = (static_cast<uint32_t>(block[20]) << 24) | (static_cast<uint32_t>(block[21]) << 16) |
               (static_cast<uint32_t>(block[22]) << 8) | static_cast<uint32_t>(block[23]);
        W[6] = (static_cast<uint32_t>(block[24]) << 24) | (static_cast<uint32_t>(block[25]) << 16) |
               (static_cast<uint32_t>(block[26]) << 8) | static_cast<uint32_t>(block[27]);
        W[7] = (static_cast<uint32_t>(block[28]) << 24) | (static_cast<uint32_t>(block[29]) << 16) |
               (static_cast<uint32_t>(block[30]) << 8) | static_cast<uint32_t>(block[31]);
        W[8] = (static_cast<uint32_t>(block[32]) << 24) | (static_cast<uint32_t>(block[33]) << 16) |
               (static_cast<uint32_t>(block[34]) << 8) | static_cast<uint32_t>(block[35]);
        W[9] = (static_cast<uint32_t>(block[36]) << 24) | (static_cast<uint32_t>(block[37]) << 16) |
               (static_cast<uint32_t>(block[38]) << 8) | static_cast<uint32_t>(block[39]);
        W[10] = (static_cast<uint32_t>(block[40]) << 24) | (static_cast<uint32_t>(block[41]) << 16) |
                (static_cast<uint32_t>(block[42]) << 8) | static_cast<uint32_t>(block[43]);
        W[11] = (static_cast<uint32_t>(block[44]) << 24) | (static_cast<uint32_t>(block[45]) << 16) |
                (static_cast<uint32_t>(block[46]) << 8) | static_cast<uint32_t>(block[47]);
        W[12] = (static_cast<uint32_t>(block[48]) << 24) | (static_cast<uint32_t>(block[49]) << 16) |
                (static_cast<uint32_t>(block[50]) << 8) | static_cast<uint32_t>(block[51]);
        W[13] = (static_cast<uint32_t>(block[52]) << 24) | (static_cast<uint32_t>(block[53]) << 16) |
                (static_cast<uint32_t>(block[54]) << 8) | static_cast<uint32_t>(block[55]);
        W[14] = (static_cast<uint32_t>(block[56]) << 24) | (static_cast<uint32_t>(block[57]) << 16) |
                (static_cast<uint32_t>(block[58]) << 8) | static_cast<uint32_t>(block[59]);
        W[15] = (static_cast<uint32_t>(block[60]) << 24) | (static_cast<uint32_t>(block[61]) << 16) |
                (static_cast<uint32_t>(block[62]) << 8) | static_cast<uint32_t>(block[63]);
        
        EXPAND_W(16, W); EXPAND_W(17, W); EXPAND_W(18, W); EXPAND_W(19, W);
        EXPAND_W(20, W); EXPAND_W(21, W); EXPAND_W(22, W); EXPAND_W(23, W);
        EXPAND_W(24, W); EXPAND_W(25, W); EXPAND_W(26, W); EXPAND_W(27, W);
        EXPAND_W(28, W); EXPAND_W(29, W); EXPAND_W(30, W); EXPAND_W(31, W);
        EXPAND_W(32, W); EXPAND_W(33, W); EXPAND_W(34, W); EXPAND_W(35, W);
        EXPAND_W(36, W); EXPAND_W(37, W); EXPAND_W(38, W); EXPAND_W(39, W);
        EXPAND_W(40, W); EXPAND_W(41, W); EXPAND_W(42, W); EXPAND_W(43, W);
        EXPAND_W(44, W); EXPAND_W(45, W); EXPAND_W(46, W); EXPAND_W(47, W);
        EXPAND_W(48, W); EXPAND_W(49, W); EXPAND_W(50, W); EXPAND_W(51, W);
        EXPAND_W(52, W); EXPAND_W(53, W); EXPAND_W(54, W); EXPAND_W(55, W);
        EXPAND_W(56, W); EXPAND_W(57, W); EXPAND_W(58, W); EXPAND_W(59, W);
        EXPAND_W(60, W); EXPAND_W(61, W); EXPAND_W(62, W); EXPAND_W(63, W);
        EXPAND_W(64, W); EXPAND_W(65, W); EXPAND_W(66, W); EXPAND_W(67, W);
        
        W_prime[0] = W[0] ^ W[4]; W_prime[1] = W[1] ^ W[5]; W_prime[2] = W[2] ^ W[6]; W_prime[3] = W[3] ^ W[7];
        W_prime[4] = W[4] ^ W[8]; W_prime[5] = W[5] ^ W[9]; W_prime[6] = W[6] ^ W[10]; W_prime[7] = W[7] ^ W[11];
        W_prime[8] = W[8] ^ W[12]; W_prime[9] = W[9] ^ W[13]; W_prime[10] = W[10] ^ W[14]; W_prime[11] = W[11] ^ W[15];
        W_prime[12] = W[12] ^ W[16]; W_prime[13] = W[13] ^ W[17]; W_prime[14] = W[14] ^ W[18]; W_prime[15] = W[15] ^ W[19];
        W_prime[16] = W[16] ^ W[20]; W_prime[17] = W[17] ^ W[21]; W_prime[18] = W[18] ^ W[22]; W_prime[19] = W[19] ^ W[23];
        W_prime[20] = W[20] ^ W[24]; W_prime[21] = W[21] ^ W[25]; W_prime[22] = W[22] ^ W[26]; W_prime[23] = W[23] ^ W[27];
        W_prime[24] = W[24] ^ W[28]; W_prime[25] = W[25] ^ W[29]; W_prime[26] = W[26] ^ W[30]; W_prime[27] = W[27] ^ W[31];
        W_prime[28] = W[28] ^ W[32]; W_prime[29] = W[29] ^ W[33]; W_prime[30] = W[30] ^ W[34]; W_prime[31] = W[31] ^ W[35];
        W_prime[32] = W[32] ^ W[36]; W_prime[33] = W[33] ^ W[37]; W_prime[34] = W[34] ^ W[38]; W_prime[35] = W[35] ^ W[39];
        W_prime[36] = W[36] ^ W[40]; W_prime[37] = W[37] ^ W[41]; W_prime[38] = W[38] ^ W[42]; W_prime[39] = W[39] ^ W[43];
        W_prime[40] = W[40] ^ W[44]; W_prime[41] = W[41] ^ W[45]; W_prime[42] = W[42] ^ W[46]; W_prime[43] = W[43] ^ W[47];
        W_prime[44] = W[44] ^ W[48]; W_prime[45] = W[45] ^ W[49]; W_prime[46] = W[46] ^ W[50]; W_prime[47] = W[47] ^ W[51];
        W_prime[48] = W[48] ^ W[52]; W_prime[49] = W[49] ^ W[53]; W_prime[50] = W[50] ^ W[54]; W_prime[51] = W[51] ^ W[55];
        W_prime[52] = W[52] ^ W[56]; W_prime[53] = W[53] ^ W[57]; W_prime[54] = W[54] ^ W[58]; W_prime[55] = W[55] ^ W[59];
        W_prime[56] = W[56] ^ W[60]; W_prime[57] = W[57] ^ W[61]; W_prime[58] = W[58] ^ W[62]; W_prime[59] = W[59] ^ W[63];
        W_prime[60] = W[60] ^ W[64]; W_prime[61] = W[61] ^ W[65]; W_prime[62] = W[62] ^ W[66]; W_prime[63] = W[63] ^ W[67];
        
        uint32_t A = H[0], B = H[1], C = H[2], D = H[3];
        uint32_t E = H[4], F = H[5], G = H[6], H_var = H[7];
        
        ROUND_0_15(0, A, B, C, D, E, F, G, H_var, W[0], W_prime[0]);
        ROUND_0_15(1, A, B, C, D, E, F, G, H_var, W[1], W_prime[1]);
        ROUND_0_15(2, A, B, C, D, E, F, G, H_var, W[2], W_prime[2]);
        ROUND_0_15(3, A, B, C, D, E, F, G, H_var, W[3], W_prime[3]);
        ROUND_0_15(4, A, B, C, D, E, F, G, H_var, W[4], W_prime[4]);
        ROUND_0_15(5, A, B, C, D, E, F, G, H_var, W[5], W_prime[5]);
        ROUND_0_15(6, A, B, C, D, E, F, G, H_var, W[6], W_prime[6]);
        ROUND_0_15(7, A, B, C, D, E, F, G, H_var, W[7], W_prime[7]);
        ROUND_0_15(8, A, B, C, D, E, F, G, H_var, W[8], W_prime[8]);
        ROUND_0_15(9, A, B, C, D, E, F, G, H_var, W[9], W_prime[9]);
        ROUND_0_15(10, A, B, C, D, E, F, G, H_var, W[10], W_prime[10]);
        ROUND_0_15(11, A, B, C, D, E, F, G, H_var, W[11], W_prime[11]);
        ROUND_0_15(12, A, B, C, D, E, F, G, H_var, W[12], W_prime[12]);
        ROUND_0_15(13, A, B, C, D, E, F, G, H_var, W[13], W_prime[13]);
        ROUND_0_15(14, A, B, C, D, E, F, G, H_var, W[14], W_prime[14]);
        ROUND_0_15(15, A, B, C, D, E, F, G, H_var, W[15], W_prime[15]);
        
        ROUND_16_63(16, A, B, C, D, E, F, G, H_var, W[16], W_prime[16]);
        ROUND_16_63(17, A, B, C, D, E, F, G, H_var, W[17], W_prime[17]);
        ROUND_16_63(18, A, B, C, D, E, F, G, H_var, W[18], W_prime[18]);
        ROUND_16_63(19, A, B, C, D, E, F, G, H_var, W[19], W_prime[19]);
        ROUND_16_63(20, A, B, C, D, E, F, G, H_var, W[20], W_prime[20]);
        ROUND_16_63(21, A, B, C, D, E, F, G, H_var, W[21], W_prime[21]);
        ROUND_16_63(22, A, B, C, D, E, F, G, H_var, W[22], W_prime[22]);
        ROUND_16_63(23, A, B, C, D, E, F, G, H_var, W[23], W_prime[23]);
        ROUND_16_63(24, A, B, C, D, E, F, G, H_var, W[24], W_prime[24]);
        ROUND_16_63(25, A, B, C, D, E, F, G, H_var, W[25], W_prime[25]);
        ROUND_16_63(26, A, B, C, D, E, F, G, H_var, W[26], W_prime[26]);
        ROUND_16_63(27, A, B, C, D, E, F, G, H_var, W[27], W_prime[27]);
        ROUND_16_63(28, A, B, C, D, E, F, G, H_var, W[28], W_prime[28]);
        ROUND_16_63(29, A, B, C, D, E, F, G, H_var, W[29], W_prime[29]);
        ROUND_16_63(30, A, B, C, D, E, F, G, H_var, W[30], W_prime[30]);
        ROUND_16_63(31, A, B, C, D, E, F, G, H_var, W[31], W_prime[31]);
        ROUND_16_63(32, A, B, C, D, E, F, G, H_var, W[32], W_prime[32]);
        ROUND_16_63(33, A, B, C, D, E, F, G, H_var, W[33], W_prime[33]);
        ROUND_16_63(34, A, B, C, D, E, F, G, H_var, W[34], W_prime[34]);
        ROUND_16_63(35, A, B, C, D, E, F, G, H_var, W[35], W_prime[35]);
        ROUND_16_63(36, A, B, C, D, E, F, G, H_var, W[36], W_prime[36]);
        ROUND_16_63(37, A, B, C, D, E, F, G, H_var, W[37], W_prime[37]);
        ROUND_16_63(38, A, B, C, D, E, F, G, H_var, W[38], W_prime[38]);
        ROUND_16_63(39, A, B, C, D, E, F, G, H_var, W[39], W_prime[39]);
        ROUND_16_63(40, A, B, C, D, E, F, G, H_var, W[40], W_prime[40]);
        ROUND_16_63(41, A, B, C, D, E, F, G, H_var, W[41], W_prime[41]);
        ROUND_16_63(42, A, B, C, D, E, F, G, H_var, W[42], W_prime[42]);
        ROUND_16_63(43, A, B, C, D, E, F, G, H_var, W[43], W_prime[43]);
        ROUND_16_63(44, A, B, C, D, E, F, G, H_var, W[44], W_prime[44]);
        ROUND_16_63(45, A, B, C, D, E, F, G, H_var, W[45], W_prime[45]);
        ROUND_16_63(46, A, B, C, D, E, F, G, H_var, W[46], W_prime[46]);
        ROUND_16_63(47, A, B, C, D, E, F, G, H_var, W[47], W_prime[47]);
        ROUND_16_63(48, A, B, C, D, E, F, G, H_var, W[48], W_prime[48]);
        ROUND_16_63(49, A, B, C, D, E, F, G, H_var, W[49], W_prime[49]);
        ROUND_16_63(50, A, B, C, D, E, F, G, H_var, W[50], W_prime[50]);
        ROUND_16_63(51, A, B, C, D, E, F, G, H_var, W[51], W_prime[51]);
        ROUND_16_63(52, A, B, C, D, E, F, G, H_var, W[52], W_prime[52]);
        ROUND_16_63(53, A, B, C, D, E, F, G, H_var, W[53], W_prime[53]);
        ROUND_16_63(54, A, B, C, D, E, F, G, H_var, W[54], W_prime[54]);
        ROUND_16_63(55, A, B, C, D, E, F, G, H_var, W[55], W_prime[55]);
        ROUND_16_63(56, A, B, C, D, E, F, G, H_var, W[56], W_prime[56]);
        ROUND_16_63(57, A, B, C, D, E, F, G, H_var, W[57], W_prime[57]);
        ROUND_16_63(58, A, B, C, D, E, F, G, H_var, W[58], W_prime[58]);
        ROUND_16_63(59, A, B, C, D, E, F, G, H_var, W[59], W_prime[59]);
        ROUND_16_63(60, A, B, C, D, E, F, G, H_var, W[60], W_prime[60]);
        ROUND_16_63(61, A, B, C, D, E, F, G, H_var, W[61], W_prime[61]);
        ROUND_16_63(62, A, B, C, D, E, F, G, H_var, W[62], W_prime[62]);
        ROUND_16_63(63, A, B, C, D, E, F, G, H_var, W[63], W_prime[63]);
        
        H[0] ^= A; H[1] ^= B; H[2] ^= C; H[3] ^= D;
        H[4] ^= E; H[5] ^= F; H[6] ^= G; H[7] ^= H_var;
    }
    
    #undef ROTL
    #undef FF_0_15
    #undef FF_16_63
    #undef GG_0_15
    #undef GG_16_63
    #undef P0
    #undef P1
    #undef TJ_0_15
    #undef TJ_16_63
    #undef ROUND_0_15
    #undef ROUND_16_63
    #undef EXPAND_W
    
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
    SM3_Flatten() {
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

const uint32_t SM3_Flatten::IV[8] = {
    0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
    0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
};

int main() {
    SM3_Flatten sm3;
    
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
