

#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <cstdint>

class SM3_RegAlloc {
private:
    static const uint32_t IV[8];
    
    uint32_t H[8];
    
    std::vector<uint8_t> buffer;
    uint64_t total_length;
    
    static inline __attribute__((always_inline)) uint32_t rotl(register uint32_t x, int n) {
        return (x << n) | (x >> (32 - n));
    }
    
    static inline __attribute__((always_inline)) uint32_t FF(register uint32_t x, register uint32_t y, register uint32_t z, int j) {
        if (j <= 15) {
            return x ^ y ^ z;
        } else {
            return (x & y) | (x & z) | (y & z);
        }
    }
    
    static inline __attribute__((always_inline)) uint32_t GG(register uint32_t x, register uint32_t y, register uint32_t z, int j) {
        if (j <= 15) {
            return x ^ y ^ z;
        } else {
            return (x & y) | (~x & z);
        }
    }
    
    static inline __attribute__((always_inline)) uint32_t P0(register uint32_t x) {
        return x ^ rotl(x, 9) ^ rotl(x, 17);
    }
    
    static inline __attribute__((always_inline)) uint32_t P1(register uint32_t x) {
        return x ^ rotl(x, 15) ^ rotl(x, 23);
    }
    
    static inline __attribute__((always_inline)) uint32_t Tj(int j) {
        return (j <= 15) ? 0x79cc4519 : 0x7a879d8a;
    }
    
    void processBlock(const uint8_t* block) {
        register uint32_t W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14, W15;
        register uint32_t W16, W17, W18, W19, W20, W21, W22, W23, W24, W25, W26, W27, W28, W29, W30, W31;
        register uint32_t W32, W33, W34, W35, W36, W37, W38, W39, W40, W41, W42, W43, W44, W45, W46, W47;
        register uint32_t W48, W49, W50, W51, W52, W53, W54, W55, W56, W57, W58, W59, W60, W61, W62, W63;
        register uint32_t W64, W65, W66, W67;
        
        W0 = (static_cast<uint32_t>(block[0]) << 24) | (static_cast<uint32_t>(block[1]) << 16) |
             (static_cast<uint32_t>(block[2]) << 8) | static_cast<uint32_t>(block[3]);
        W1 = (static_cast<uint32_t>(block[4]) << 24) | (static_cast<uint32_t>(block[5]) << 16) |
             (static_cast<uint32_t>(block[6]) << 8) | static_cast<uint32_t>(block[7]);
        W2 = (static_cast<uint32_t>(block[8]) << 24) | (static_cast<uint32_t>(block[9]) << 16) |
             (static_cast<uint32_t>(block[10]) << 8) | static_cast<uint32_t>(block[11]);
        W3 = (static_cast<uint32_t>(block[12]) << 24) | (static_cast<uint32_t>(block[13]) << 16) |
             (static_cast<uint32_t>(block[14]) << 8) | static_cast<uint32_t>(block[15]);
        W4 = (static_cast<uint32_t>(block[16]) << 24) | (static_cast<uint32_t>(block[17]) << 16) |
             (static_cast<uint32_t>(block[18]) << 8) | static_cast<uint32_t>(block[19]);
        W5 = (static_cast<uint32_t>(block[20]) << 24) | (static_cast<uint32_t>(block[21]) << 16) |
             (static_cast<uint32_t>(block[22]) << 8) | static_cast<uint32_t>(block[23]);
        W6 = (static_cast<uint32_t>(block[24]) << 24) | (static_cast<uint32_t>(block[25]) << 16) |
             (static_cast<uint32_t>(block[26]) << 8) | static_cast<uint32_t>(block[27]);
        W7 = (static_cast<uint32_t>(block[28]) << 24) | (static_cast<uint32_t>(block[29]) << 16) |
             (static_cast<uint32_t>(block[30]) << 8) | static_cast<uint32_t>(block[31]);
        W8 = (static_cast<uint32_t>(block[32]) << 24) | (static_cast<uint32_t>(block[33]) << 16) |
             (static_cast<uint32_t>(block[34]) << 8) | static_cast<uint32_t>(block[35]);
        W9 = (static_cast<uint32_t>(block[36]) << 24) | (static_cast<uint32_t>(block[37]) << 16) |
             (static_cast<uint32_t>(block[38]) << 8) | static_cast<uint32_t>(block[39]);
        W10 = (static_cast<uint32_t>(block[40]) << 24) | (static_cast<uint32_t>(block[41]) << 16) |
              (static_cast<uint32_t>(block[42]) << 8) | static_cast<uint32_t>(block[43]);
        W11 = (static_cast<uint32_t>(block[44]) << 24) | (static_cast<uint32_t>(block[45]) << 16) |
              (static_cast<uint32_t>(block[46]) << 8) | static_cast<uint32_t>(block[47]);
        W12 = (static_cast<uint32_t>(block[48]) << 24) | (static_cast<uint32_t>(block[49]) << 16) |
              (static_cast<uint32_t>(block[50]) << 8) | static_cast<uint32_t>(block[51]);
        W13 = (static_cast<uint32_t>(block[52]) << 24) | (static_cast<uint32_t>(block[53]) << 16) |
              (static_cast<uint32_t>(block[54]) << 8) | static_cast<uint32_t>(block[55]);
        W14 = (static_cast<uint32_t>(block[56]) << 24) | (static_cast<uint32_t>(block[57]) << 16) |
              (static_cast<uint32_t>(block[58]) << 8) | static_cast<uint32_t>(block[59]);
        W15 = (static_cast<uint32_t>(block[60]) << 24) | (static_cast<uint32_t>(block[61]) << 16) |
              (static_cast<uint32_t>(block[62]) << 8) | static_cast<uint32_t>(block[63]);
        
        W16 = P1(W0 ^ W7 ^ rotl(W13, 15)) ^ rotl(W3, 7) ^ W10;
        W17 = P1(W1 ^ W8 ^ rotl(W14, 15)) ^ rotl(W4, 7) ^ W11;
        W18 = P1(W2 ^ W9 ^ rotl(W15, 15)) ^ rotl(W5, 7) ^ W12;
        W19 = P1(W3 ^ W10 ^ rotl(W16, 15)) ^ rotl(W6, 7) ^ W13;
        W20 = P1(W4 ^ W11 ^ rotl(W17, 15)) ^ rotl(W7, 7) ^ W14;
        W21 = P1(W5 ^ W12 ^ rotl(W18, 15)) ^ rotl(W8, 7) ^ W15;
        W22 = P1(W6 ^ W13 ^ rotl(W19, 15)) ^ rotl(W9, 7) ^ W16;
        W23 = P1(W7 ^ W14 ^ rotl(W20, 15)) ^ rotl(W10, 7) ^ W17;
        W24 = P1(W8 ^ W15 ^ rotl(W21, 15)) ^ rotl(W11, 7) ^ W18;
        W25 = P1(W9 ^ W16 ^ rotl(W22, 15)) ^ rotl(W12, 7) ^ W19;
        W26 = P1(W10 ^ W17 ^ rotl(W23, 15)) ^ rotl(W13, 7) ^ W20;
        W27 = P1(W11 ^ W18 ^ rotl(W24, 15)) ^ rotl(W14, 7) ^ W21;
        W28 = P1(W12 ^ W19 ^ rotl(W25, 15)) ^ rotl(W15, 7) ^ W22;
        W29 = P1(W13 ^ W20 ^ rotl(W26, 15)) ^ rotl(W16, 7) ^ W23;
        W30 = P1(W14 ^ W21 ^ rotl(W27, 15)) ^ rotl(W17, 7) ^ W24;
        W31 = P1(W15 ^ W22 ^ rotl(W28, 15)) ^ rotl(W18, 7) ^ W25;
        W32 = P1(W16 ^ W23 ^ rotl(W29, 15)) ^ rotl(W19, 7) ^ W26;
        W33 = P1(W17 ^ W24 ^ rotl(W30, 15)) ^ rotl(W20, 7) ^ W27;
        W34 = P1(W18 ^ W25 ^ rotl(W31, 15)) ^ rotl(W21, 7) ^ W28;
        W35 = P1(W19 ^ W26 ^ rotl(W32, 15)) ^ rotl(W22, 7) ^ W29;
        W36 = P1(W20 ^ W27 ^ rotl(W33, 15)) ^ rotl(W23, 7) ^ W30;
        W37 = P1(W21 ^ W28 ^ rotl(W34, 15)) ^ rotl(W24, 7) ^ W31;
        W38 = P1(W22 ^ W29 ^ rotl(W35, 15)) ^ rotl(W25, 7) ^ W32;
        W39 = P1(W23 ^ W30 ^ rotl(W36, 15)) ^ rotl(W26, 7) ^ W33;
        W40 = P1(W24 ^ W31 ^ rotl(W37, 15)) ^ rotl(W27, 7) ^ W34;
        W41 = P1(W25 ^ W32 ^ rotl(W38, 15)) ^ rotl(W28, 7) ^ W35;
        W42 = P1(W26 ^ W33 ^ rotl(W39, 15)) ^ rotl(W29, 7) ^ W36;
        W43 = P1(W27 ^ W34 ^ rotl(W40, 15)) ^ rotl(W30, 7) ^ W37;
        W44 = P1(W28 ^ W35 ^ rotl(W41, 15)) ^ rotl(W31, 7) ^ W38;
        W45 = P1(W29 ^ W36 ^ rotl(W42, 15)) ^ rotl(W32, 7) ^ W39;
        W46 = P1(W30 ^ W37 ^ rotl(W43, 15)) ^ rotl(W33, 7) ^ W40;
        W47 = P1(W31 ^ W38 ^ rotl(W44, 15)) ^ rotl(W34, 7) ^ W41;
        W48 = P1(W32 ^ W39 ^ rotl(W45, 15)) ^ rotl(W35, 7) ^ W42;
        W49 = P1(W33 ^ W40 ^ rotl(W46, 15)) ^ rotl(W36, 7) ^ W43;
        W50 = P1(W34 ^ W41 ^ rotl(W47, 15)) ^ rotl(W37, 7) ^ W44;
        W51 = P1(W35 ^ W42 ^ rotl(W48, 15)) ^ rotl(W38, 7) ^ W45;
        W52 = P1(W36 ^ W43 ^ rotl(W49, 15)) ^ rotl(W39, 7) ^ W46;
        W53 = P1(W37 ^ W44 ^ rotl(W50, 15)) ^ rotl(W40, 7) ^ W47;
        W54 = P1(W38 ^ W45 ^ rotl(W51, 15)) ^ rotl(W41, 7) ^ W48;
        W55 = P1(W39 ^ W46 ^ rotl(W52, 15)) ^ rotl(W42, 7) ^ W49;
        W56 = P1(W40 ^ W47 ^ rotl(W53, 15)) ^ rotl(W43, 7) ^ W50;
        W57 = P1(W41 ^ W48 ^ rotl(W54, 15)) ^ rotl(W44, 7) ^ W51;
        W58 = P1(W42 ^ W49 ^ rotl(W55, 15)) ^ rotl(W45, 7) ^ W52;
        W59 = P1(W43 ^ W50 ^ rotl(W56, 15)) ^ rotl(W46, 7) ^ W53;
        W60 = P1(W44 ^ W51 ^ rotl(W57, 15)) ^ rotl(W47, 7) ^ W54;
        W61 = P1(W45 ^ W52 ^ rotl(W58, 15)) ^ rotl(W48, 7) ^ W55;
        W62 = P1(W46 ^ W53 ^ rotl(W59, 15)) ^ rotl(W49, 7) ^ W56;
        W63 = P1(W47 ^ W54 ^ rotl(W60, 15)) ^ rotl(W50, 7) ^ W57;
        W64 = P1(W48 ^ W55 ^ rotl(W61, 15)) ^ rotl(W51, 7) ^ W58;
        W65 = P1(W49 ^ W56 ^ rotl(W62, 15)) ^ rotl(W52, 7) ^ W59;
        W66 = P1(W50 ^ W57 ^ rotl(W63, 15)) ^ rotl(W53, 7) ^ W60;
        W67 = P1(W51 ^ W58 ^ rotl(W64, 15)) ^ rotl(W54, 7) ^ W61;
        
        register uint32_t A = H[0], B = H[1], C = H[2], D = H[3];
        register uint32_t E = H[4], F = H[5], G = H[6], H_var = H[7];
        
        for (int j = 0; j < 64; j++) {
            register uint32_t W_val, W_prime_val;
            
            switch(j) {
                case 0: W_val = W0; break; case 1: W_val = W1; break; case 2: W_val = W2; break; case 3: W_val = W3; break;
                case 4: W_val = W4; break; case 5: W_val = W5; break; case 6: W_val = W6; break; case 7: W_val = W7; break;
                case 8: W_val = W8; break; case 9: W_val = W9; break; case 10: W_val = W10; break; case 11: W_val = W11; break;
                case 12: W_val = W12; break; case 13: W_val = W13; break; case 14: W_val = W14; break; case 15: W_val = W15; break;
                case 16: W_val = W16; break; case 17: W_val = W17; break; case 18: W_val = W18; break; case 19: W_val = W19; break;
                case 20: W_val = W20; break; case 21: W_val = W21; break; case 22: W_val = W22; break; case 23: W_val = W23; break;
                case 24: W_val = W24; break; case 25: W_val = W25; break; case 26: W_val = W26; break; case 27: W_val = W27; break;
                case 28: W_val = W28; break; case 29: W_val = W29; break; case 30: W_val = W30; break; case 31: W_val = W31; break;
                case 32: W_val = W32; break; case 33: W_val = W33; break; case 34: W_val = W34; break; case 35: W_val = W35; break;
                case 36: W_val = W36; break; case 37: W_val = W37; break; case 38: W_val = W38; break; case 39: W_val = W39; break;
                case 40: W_val = W40; break; case 41: W_val = W41; break; case 42: W_val = W42; break; case 43: W_val = W43; break;
                case 44: W_val = W44; break; case 45: W_val = W45; break; case 46: W_val = W46; break; case 47: W_val = W47; break;
                case 48: W_val = W48; break; case 49: W_val = W49; break; case 50: W_val = W50; break; case 51: W_val = W51; break;
                case 52: W_val = W52; break; case 53: W_val = W53; break; case 54: W_val = W54; break; case 55: W_val = W55; break;
                case 56: W_val = W56; break; case 57: W_val = W57; break; case 58: W_val = W58; break; case 59: W_val = W59; break;
                case 60: W_val = W60; break; case 61: W_val = W61; break; case 62: W_val = W62; break; case 63: W_val = W63; break;
            }
            
            switch(j) {
                case 0: W_prime_val = W0 ^ W4; break; case 1: W_prime_val = W1 ^ W5; break;
                case 2: W_prime_val = W2 ^ W6; break; case 3: W_prime_val = W3 ^ W7; break;
                case 4: W_prime_val = W4 ^ W8; break; case 5: W_prime_val = W5 ^ W9; break;
                case 6: W_prime_val = W6 ^ W10; break; case 7: W_prime_val = W7 ^ W11; break;
                case 8: W_prime_val = W8 ^ W12; break; case 9: W_prime_val = W9 ^ W13; break;
                case 10: W_prime_val = W10 ^ W14; break; case 11: W_prime_val = W11 ^ W15; break;
                case 12: W_prime_val = W12 ^ W16; break; case 13: W_prime_val = W13 ^ W17; break;
                case 14: W_prime_val = W14 ^ W18; break; case 15: W_prime_val = W15 ^ W19; break;
                case 16: W_prime_val = W16 ^ W20; break; case 17: W_prime_val = W17 ^ W21; break;
                case 18: W_prime_val = W18 ^ W22; break; case 19: W_prime_val = W19 ^ W23; break;
                case 20: W_prime_val = W20 ^ W24; break; case 21: W_prime_val = W21 ^ W25; break;
                case 22: W_prime_val = W22 ^ W26; break; case 23: W_prime_val = W23 ^ W27; break;
                case 24: W_prime_val = W24 ^ W28; break; case 25: W_prime_val = W25 ^ W29; break;
                case 26: W_prime_val = W26 ^ W30; break; case 27: W_prime_val = W27 ^ W31; break;
                case 28: W_prime_val = W28 ^ W32; break; case 29: W_prime_val = W29 ^ W33; break;
                case 30: W_prime_val = W30 ^ W34; break; case 31: W_prime_val = W31 ^ W35; break;
                case 32: W_prime_val = W32 ^ W36; break; case 33: W_prime_val = W33 ^ W37; break;
                case 34: W_prime_val = W34 ^ W38; break; case 35: W_prime_val = W35 ^ W39; break;
                case 36: W_prime_val = W36 ^ W40; break; case 37: W_prime_val = W37 ^ W41; break;
                case 38: W_prime_val = W38 ^ W42; break; case 39: W_prime_val = W39 ^ W43; break;
                case 40: W_prime_val = W40 ^ W44; break; case 41: W_prime_val = W41 ^ W45; break;
                case 42: W_prime_val = W42 ^ W46; break; case 43: W_prime_val = W43 ^ W47; break;
                case 44: W_prime_val = W44 ^ W48; break; case 45: W_prime_val = W45 ^ W49; break;
                case 46: W_prime_val = W46 ^ W50; break; case 47: W_prime_val = W47 ^ W51; break;
                case 48: W_prime_val = W48 ^ W52; break; case 49: W_prime_val = W49 ^ W53; break;
                case 50: W_prime_val = W50 ^ W54; break; case 51: W_prime_val = W51 ^ W55; break;
                case 52: W_prime_val = W52 ^ W56; break; case 53: W_prime_val = W53 ^ W57; break;
                case 54: W_prime_val = W54 ^ W58; break; case 55: W_prime_val = W55 ^ W59; break;
                case 56: W_prime_val = W56 ^ W60; break; case 57: W_prime_val = W57 ^ W61; break;
                case 58: W_prime_val = W58 ^ W62; break; case 59: W_prime_val = W59 ^ W63; break;
                case 60: W_prime_val = W60 ^ W64; break; case 61: W_prime_val = W61 ^ W65; break;
                case 62: W_prime_val = W62 ^ W66; break; case 63: W_prime_val = W63 ^ W67; break;
            }
            
            register uint32_t SS1 = rotl((rotl(A, 12) + E + rotl(Tj(j), j % 32)), 7);
            register uint32_t SS2 = SS1 ^ rotl(A, 12);
            register uint32_t TT1 = FF(A, B, C, j) + D + SS2 + W_prime_val;
            register uint32_t TT2 = GG(E, F, G, j) + H_var + SS1 + W_val;
            
            D = C;
            C = rotl(B, 9);
            B = A;
            A = TT1;
            H_var = G;
            G = rotl(F, 19);
            F = E;
            E = P0(TT2);
        }
        
        H[0] ^= A; H[1] ^= B; H[2] ^= C; H[3] ^= D;
        H[4] ^= E; H[5] ^= F; H[6] ^= G; H[7] ^= H_var;
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
    SM3_RegAlloc() {
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

const uint32_t SM3_RegAlloc::IV[8] = {
    0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
    0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
};

int main() {
    SM3_RegAlloc sm3;
    
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
