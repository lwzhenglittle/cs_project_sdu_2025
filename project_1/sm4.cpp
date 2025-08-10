#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cassert>
#include <cstdint>

class SM4 {
private:
    static const uint8_t SBOX[256];
    
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
    
    static uint32_t tau(uint32_t A) {
        uint8_t a0 = (A >> 24) & 0xFF;
        uint8_t a1 = (A >> 16) & 0xFF;
        uint8_t a2 = (A >> 8) & 0xFF;
        uint8_t a3 = A & 0xFF;
        
        return (static_cast<uint32_t>(SBOX[a0]) << 24) |
               (static_cast<uint32_t>(SBOX[a1]) << 16) |
               (static_cast<uint32_t>(SBOX[a2]) << 8) |
               static_cast<uint32_t>(SBOX[a3]);
    }
    
    static uint32_t L(uint32_t B) {
        return B ^ left_rotate(B, 2) ^ left_rotate(B, 10) ^ left_rotate(B, 18) ^ left_rotate(B, 24);
    }
    
    static uint32_t L_prime(uint32_t B) {
        return B ^ left_rotate(B, 13) ^ left_rotate(B, 23);
    }
    
    static uint32_t left_rotate(uint32_t value, int bits) {
        return (value << bits) | (value >> (32 - bits));
    }
    
    static uint32_t T(uint32_t X) {
        return L(tau(X));
    }
    
    static uint32_t T_prime(uint32_t X) {
        return L_prime(tau(X));
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
    
    static std::vector<uint8_t> encrypt_block(const std::vector<uint8_t>& plaintext, 
                                             const std::vector<uint32_t>& round_keys) {
        uint32_t X[36];
        for (int i = 0; i < 4; i++) {
            X[i] = bytes_to_uint32(plaintext, i * 4);
        }
        
        for (int i = 0; i < 32; i++) {
            X[i + 4] = X[i] ^ T(X[i + 1] ^ X[i + 2] ^ X[i + 3] ^ round_keys[i]);
        }
        
        std::vector<uint8_t> ciphertext;
        for (int i = 3; i >= 0; i--) {
            auto bytes = uint32_to_bytes(X[32 + i]);
            ciphertext.insert(ciphertext.end(), bytes.begin(), bytes.end());
        }
        
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
        for (size_t i = 0; i < plain_hex.length(); i += 32) {
            std::string block = plain_hex.substr(i, 32);
            auto plaintext_block = hex_to_bytes(block);
            auto ciphertext_block = encrypt_block(plaintext_block, round_keys);
            result += bytes_to_hex(ciphertext_block);
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

const uint8_t SM4::SBOX[256] = {
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
};

const uint32_t SM4::FK[4] = {
    0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc
};

const uint32_t SM4::CK[32] = {
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
    return SM4::encrypt_block_hex(plain_hex, key_hex);
}

std::string decrypt_block_hex(const std::string &cipher_hex, const std::string &key_hex) {
    return SM4::decrypt_block_hex(cipher_hex, key_hex);
}

std::string encrypt_hex(const std::string &plain_hex, const std::string &key_hex) {
    return SM4::encrypt_hex(plain_hex, key_hex);
}

std::string decrypt_hex(const std::string &cipher_hex, const std::string &key_hex) {
    return SM4::decrypt_hex(cipher_hex, key_hex);
}

int main() {
    std::string operation, input_hex, key_hex;
    
    std::cout << "SM4 Cipher - Enter operation (encrypt/decrypt): ";
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
