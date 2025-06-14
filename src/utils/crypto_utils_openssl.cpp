// Proper AES-128-CTR implementation using OpenSSL for JavaScript compatibility
// This file should replace the simple XOR implementation in crypto_utils.cpp
#include "utils/crypto_utils.h"
#include "utils/logger.h"
#include "common/error_codes.h"
#include "common/constants.h"

#include <openssl/evp.h>
#include <openssl/aes.h>
#undef AES_BLOCK_SIZE  // Cancel the definition of AES_BLOCK_SIZE in OpenSSL
#include <openssl/rand.h>
#include <random>
#include <chrono>
#include <cstring>
#include <algorithm>

namespace xiaozhi {
namespace crypto {

AudioCrypto::AudioCrypto() : initialized_(false) {
}

AudioCrypto::~AudioCrypto() {
}

int AudioCrypto::Initialize(const std::vector<uint8_t>& key) {
    if (key.size() != constants::AES_KEY_SIZE) {
        LOG_ERROR("Invalid AES key size: " + std::to_string(key.size()) + ", expected: " + std::to_string(constants::AES_KEY_SIZE));
        return error::CRYPTO_INVALID_KEY;
    }
    
    key_ = key;
    initialized_ = true;
    
    LOG_DEBUG("Audio crypto initialized with AES-128 key");
    return error::SUCCESS;
}

int AudioCrypto::Encrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& header, std::vector<uint8_t>& encrypted_data) {
    if (!initialized_) {
        LOG_ERROR("Audio crypto not initialized");
        return error::CRYPTO_INIT_FAILED;
    }
    
    if (header.size() != constants::AES_BLOCK_SIZE) {
        LOG_ERROR("Invalid header size for IV: " + std::to_string(header.size()) + ", expected: " + std::to_string(constants::AES_BLOCK_SIZE));
        return error::CRYPTO_INVALID_IV;
    }
    
    if (data.empty()) {
        encrypted_data.clear();
        return error::SUCCESS;
    }
    
    int ret = PerformAES128CTR(data, key_, header, encrypted_data);
    if (ret != error::SUCCESS) {
        LOG_ERROR("AES encryption failed");
        return error::CRYPTO_ENCRYPTION_FAILED;
    }
    
    LOG_DEBUG("Encrypted audio data: " + std::to_string(data.size()) + " bytes");
    return error::SUCCESS;
}

int AudioCrypto::Decrypt(const std::vector<uint8_t>& encrypted_data, const std::vector<uint8_t>& header, std::vector<uint8_t>& data) {
    if (!initialized_) {
        LOG_ERROR("Audio crypto not initialized");
        return error::CRYPTO_INIT_FAILED;
    }
    
    if (header.size() != constants::AES_BLOCK_SIZE) {
        LOG_ERROR("Invalid header size for IV: " + std::to_string(header.size()) + ", expected: " + std::to_string(constants::AES_BLOCK_SIZE));
        return error::CRYPTO_INVALID_IV;
    }
    
    if (encrypted_data.empty()) {
        data.clear();
        return error::SUCCESS;
    }
    
    // AES-CTR is symmetric, so decryption is the same as encryption
    int ret = PerformAES128CTR(encrypted_data, key_, header, data);
    if (ret != error::SUCCESS) {
        LOG_ERROR("AES decryption failed");
        return error::CRYPTO_DECRYPTION_FAILED;
    }
    
    LOG_DEBUG("Decrypted audio data: " + std::to_string(encrypted_data.size()) + " bytes");
    return error::SUCCESS;
}

std::vector<uint8_t> AudioCrypto::GenerateKey() {
    std::vector<uint8_t> key(constants::AES_KEY_SIZE);
    
    // Use OpenSSL's secure random number generator
    if (RAND_bytes(key.data(), key.size()) != 1) {
        // Fallback to C++ random if OpenSSL fails
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<int> dis(0, 255);

        for (size_t i = 0; i < key.size(); ++i) {
            key[i] = static_cast<uint8_t>(dis(gen));
        }
        LOG_WARN("OpenSSL RAND_bytes failed, using fallback random generator");
    }
    
    LOG_DEBUG("Generated AES-128 key");
    return key;
}

int AudioCrypto::PerformAES128CTR(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key, 
                                 const std::vector<uint8_t>& iv, std::vector<uint8_t>& output) {
    // Create and initialize the context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        LOG_ERROR("Failed to create EVP_CIPHER_CTX");
        return error::CRYPTO_INIT_FAILED;
    }
    
    // Initialize AES-128-CTR
    // Note: For CTR mode, encryption and decryption are the same operation
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), nullptr, key.data(), iv.data()) != 1) {
        LOG_ERROR("Failed to initialize AES-128-CTR");
        EVP_CIPHER_CTX_free(ctx);
        return error::CRYPTO_INIT_FAILED;
    }
    
    // Prepare output buffer
    output.resize(data.size() + constants::AES_BLOCK_SIZE); // Extra space for potential padding
    int len;
    int ciphertext_len = 0;
    
    // Encrypt/Decrypt data
    if (EVP_EncryptUpdate(ctx, output.data(), &len, data.data(), data.size()) != 1) {
        LOG_ERROR("Failed to encrypt/decrypt data");
        EVP_CIPHER_CTX_free(ctx);
        return error::CRYPTO_ENCRYPTION_FAILED;
    }
    ciphertext_len = len;
    
    // Finalize (CTR mode doesn't add padding, but we call it for completeness)
    if (EVP_EncryptFinal_ex(ctx, output.data() + len, &len) != 1) {
        LOG_ERROR("Failed to finalize encryption/decryption");
        EVP_CIPHER_CTX_free(ctx);
        return error::CRYPTO_ENCRYPTION_FAILED;
    }
    ciphertext_len += len;
    
    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    
    // Resize output to actual size (CTR mode output is same size as input)
    output.resize(ciphertext_len);
    
    return error::SUCCESS;
}

// UDP Header Generator Implementation (unchanged from original)
int UDPHeaderGenerator::GenerateHeader(uint32_t connection_id, uint16_t length, uint32_t timestamp, 
                                      uint32_t sequence, std::vector<uint8_t>& header) {
    header.resize(16);
    
    // Format matches JavaScript implementation:
    // [1 byte: type][1 byte: reserved][2 bytes: length][4 bytes: connection_id][4 bytes: timestamp][4 bytes: sequence]
    
    header[0] = 1;  // Type (audio data)
    header[1] = 0;  // Reserved
    
    // Length (big-endian)
    header[2] = static_cast<uint8_t>((length >> 8) & 0xFF);
    header[3] = static_cast<uint8_t>(length & 0xFF);
    
    // Connection ID (big-endian)
    header[4] = static_cast<uint8_t>((connection_id >> 24) & 0xFF);
    header[5] = static_cast<uint8_t>((connection_id >> 16) & 0xFF);
    header[6] = static_cast<uint8_t>((connection_id >> 8) & 0xFF);
    header[7] = static_cast<uint8_t>(connection_id & 0xFF);
    
    // Timestamp (big-endian)
    header[8] = static_cast<uint8_t>((timestamp >> 24) & 0xFF);
    header[9] = static_cast<uint8_t>((timestamp >> 16) & 0xFF);
    header[10] = static_cast<uint8_t>((timestamp >> 8) & 0xFF);
    header[11] = static_cast<uint8_t>(timestamp & 0xFF);
    
    // Sequence (big-endian)
    header[12] = static_cast<uint8_t>((sequence >> 24) & 0xFF);
    header[13] = static_cast<uint8_t>((sequence >> 16) & 0xFF);
    header[14] = static_cast<uint8_t>((sequence >> 8) & 0xFF);
    header[15] = static_cast<uint8_t>(sequence & 0xFF);
    
    return error::SUCCESS;
}

int UDPHeaderGenerator::ParseHeader(const std::vector<uint8_t>& header, uint32_t& connection_id, 
                                   uint16_t& length, uint32_t& timestamp, uint32_t& sequence) {
    if (header.size() != 16) {
        return error::UDP_INVALID_HEADER;
    }
    
    // Parse length (big-endian)
    length = (static_cast<uint16_t>(header[2]) << 8) | static_cast<uint16_t>(header[3]);
    
    // Parse connection ID (big-endian)
    connection_id = (static_cast<uint32_t>(header[4]) << 24) |
                   (static_cast<uint32_t>(header[5]) << 16) |
                   (static_cast<uint32_t>(header[6]) << 8) |
                   static_cast<uint32_t>(header[7]);
    
    // Parse timestamp (big-endian)
    timestamp = (static_cast<uint32_t>(header[8]) << 24) |
               (static_cast<uint32_t>(header[9]) << 16) |
               (static_cast<uint32_t>(header[10]) << 8) |
               static_cast<uint32_t>(header[11]);
    
    // Parse sequence (big-endian)
    sequence = (static_cast<uint32_t>(header[12]) << 24) |
              (static_cast<uint32_t>(header[13]) << 16) |
              (static_cast<uint32_t>(header[14]) << 8) |
              static_cast<uint32_t>(header[15]);
    
    return error::SUCCESS;
}

int UDPHeaderGenerator::GenerateWebSocketAudioPacket(const std::vector<uint8_t>& opus_data,
                                                    uint32_t timestamp,
                                                    std::vector<uint8_t>& packet) {
    // JavaScript WebSocket audio packet format:
    // [unknown: 8 bytes][timestamp: 4u BE][opusLength: 4u BE][opus: opusLength bytes]

    packet.clear();
    packet.resize(16 + opus_data.size());

    // First 8 bytes unknown data (undefined in JavaScript, set to 0)
    std::fill(packet.begin(), packet.begin() + 8, 0);

    // Timestamp (big-endian, offset 8)
    packet[8] = static_cast<uint8_t>((timestamp >> 24) & 0xFF);
    packet[9] = static_cast<uint8_t>((timestamp >> 16) & 0xFF);
    packet[10] = static_cast<uint8_t>((timestamp >> 8) & 0xFF);
    packet[11] = static_cast<uint8_t>(timestamp & 0xFF);

    // Opus length (big-endian, offset 12)
    uint32_t opus_length = static_cast<uint32_t>(opus_data.size());
    packet[12] = static_cast<uint8_t>((opus_length >> 24) & 0xFF);
    packet[13] = static_cast<uint8_t>((opus_length >> 16) & 0xFF);
    packet[14] = static_cast<uint8_t>((opus_length >> 8) & 0xFF);
    packet[15] = static_cast<uint8_t>(opus_length & 0xFF);

    // Opus audio data (offset 16)
    std::copy(opus_data.begin(), opus_data.end(), packet.begin() + 16);

    return error::SUCCESS;
}

int UDPHeaderGenerator::ParseWebSocketAudioPacket(const std::vector<uint8_t>& packet,
                                                 std::vector<uint8_t>& opus_data,
                                                 uint32_t& timestamp) {
    // JavaScript WebSocket audio packet parsing:
    // const timestamp = data.readUInt32BE(8);
    // const opusLength = data.readUInt32BE(12);
    // const opus = data.subarray(16, 16 + opusLength);

    if (packet.size() < 16) {
        return error::UDP_INVALID_PACKET;
    }

    // Parse timestamp (big-endian, offset 8)
    timestamp = (static_cast<uint32_t>(packet[8]) << 24) |
               (static_cast<uint32_t>(packet[9]) << 16) |
               (static_cast<uint32_t>(packet[10]) << 8) |
               static_cast<uint32_t>(packet[11]);

    // Parse Opus length (big-endian, offset 12)
    uint32_t opus_length = (static_cast<uint32_t>(packet[12]) << 24) |
                          (static_cast<uint32_t>(packet[13]) << 16) |
                          (static_cast<uint32_t>(packet[14]) << 8) |
                          static_cast<uint32_t>(packet[15]);

    // Check data length
    if (packet.size() < 16 + opus_length) {
        return error::UDP_INVALID_PACKET;
    }

    // Extract Opus audio data (offset 16)
    opus_data.assign(packet.begin() + 16, packet.begin() + 16 + opus_length);

    return error::SUCCESS;
}

namespace utils {

std::vector<uint8_t> CreateKeyFromSessionId(const std::string& session_id) {
    // Use OpenSSL to create a proper key derivation
    std::vector<uint8_t> key(constants::AES_KEY_SIZE);
    
    // Simple key derivation using SHA-256 (truncated to 128 bits)
    // In production, use proper KDF like PBKDF2
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (mdctx) {
        if (EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) == 1 &&
            EVP_DigestUpdate(mdctx, session_id.c_str(), session_id.length()) == 1) {
            
            unsigned char hash[EVP_MAX_MD_SIZE];
            unsigned int hash_len;
            
            if (EVP_DigestFinal_ex(mdctx, hash, &hash_len) == 1) {
                // Take first 16 bytes of SHA-256 hash as AES-128 key
                std::copy(hash, hash + constants::AES_KEY_SIZE, key.begin());
            }
        }
        EVP_MD_CTX_free(mdctx);
    } else {
        // Fallback to simple hash-based derivation
        std::hash<std::string> hasher;
        size_t hash = hasher(session_id);
        
        for (size_t i = 0; i < key.size(); ++i) {
            key[i] = static_cast<uint8_t>((hash >> (i * 8)) & 0xFF);
        }
    }
    
    return key;
}

std::string EncodeBase64(const std::vector<uint8_t>& data) {
    // Simple base64 encoding
    static const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result;
    
    for (size_t i = 0; i < data.size(); i += 3) {
        uint32_t val = 0;
        int padding = 0;
        
        for (int j = 0; j < 3; ++j) {
            val <<= 8;
            if (i + j < data.size()) {
                val |= data[i + j];
            } else {
                padding++;
            }
        }
        
        for (int j = 0; j < 4; ++j) {
            if (j < 4 - padding) {
                result += chars[(val >> (18 - j * 6)) & 0x3F];
            } else {
                result += '=';
            }
        }
    }
    
    return result;
}

std::vector<uint8_t> DecodeBase64(const std::string& base64_str) {
    // Simple base64 decoding
    static const int decode_table[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
    };
    
    std::vector<uint8_t> result;
    
    for (size_t i = 0; i < base64_str.length(); i += 4) {
        uint32_t val = 0;
        int padding = 0;
        
        for (int j = 0; j < 4; ++j) {
            val <<= 6;
            if (i + j < base64_str.length() && base64_str[i + j] != '=') {
                int decoded = decode_table[static_cast<unsigned char>(base64_str[i + j])];
                if (decoded >= 0) {
                    val |= decoded;
                }
            } else {
                padding++;
            }
        }
        
        for (int j = 0; j < 3 - padding; ++j) {
            result.push_back(static_cast<uint8_t>((val >> (16 - j * 8)) & 0xFF));
        }
    }
    
    return result;
}

} // namespace utils
} // namespace crypto
} // namespace xiaozhi
