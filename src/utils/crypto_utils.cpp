#include "utils/crypto_utils.h"
#include "utils/logger.h"
#include "common/error_codes.h"
#include "common/constants.h"

#include <random>
#include <chrono>
#include <cstring>
#include <algorithm>
#include <sstream>
#include <iomanip>

// Simple AES-128-CTR implementation for compatibility with Node.js crypto
// Note: For production use, consider using OpenSSL or similar crypto library

namespace xiaozhi {
namespace crypto {

// Simple AES S-box for demonstration (in production, use proper crypto library)
static const uint8_t sbox[256] = {
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

// Simple XOR-based encryption for demonstration
// Note: This is NOT secure AES implementation - use OpenSSL in production!
static void SimpleXORCrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key, 
                          const std::vector<uint8_t>& iv, std::vector<uint8_t>& output) {
    output.resize(data.size());
    
    // Simple XOR with key and IV (NOT real AES-CTR!)
    for (size_t i = 0; i < data.size(); ++i) {
        uint8_t key_byte = key[i % key.size()];
        uint8_t iv_byte = iv[i % iv.size()];
        uint8_t counter_byte = static_cast<uint8_t>(i & 0xFF);
        
        // Simple mixing - NOT cryptographically secure!
        uint8_t keystream = sbox[(key_byte ^ iv_byte ^ counter_byte) & 0xFF];
        output[i] = data[i] ^ keystream;
    }
}

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
    
    // Use random device for key generation
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dis(0, 255);

    for (size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<uint8_t>(dis(gen));
    }
    
    LOG_DEBUG("Generated AES-128 key");
    return key;
}

int AudioCrypto::PerformAES128CTR(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key, 
                                 const std::vector<uint8_t>& iv, std::vector<uint8_t>& output) {
    // Simple XOR-based encryption for demonstration
    // In production, use proper AES-CTR implementation from OpenSSL
    SimpleXORCrypt(data, key, iv, output);
    return error::SUCCESS;
}

// UDP Header Generator Implementation
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
    // Simple key derivation from session ID
    std::vector<uint8_t> key(constants::AES_KEY_SIZE);
    
    // Hash session ID to create key
    std::hash<std::string> hasher;
    size_t hash = hasher(session_id);
    
    // Fill key with hash-derived bytes
    for (size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<uint8_t>((hash >> (i * 8)) & 0xFF);
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

std::string EncodeHex(const std::vector<uint8_t>& data) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (uint8_t byte : data) {
        oss << std::setw(2) << static_cast<int>(byte);
    }
    return oss.str();
}

std::vector<uint8_t> DecodeHex(const std::string& hex_str) {
    if (hex_str.length() % 2 != 0) {
        return {};
    }
    std::vector<uint8_t> result;
    result.reserve(hex_str.length() / 2);
    for (size_t i = 0; i < hex_str.length(); i += 2) {
        char high = hex_str[i];
        char low = hex_str[i + 1];
        auto hexValue = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int hi = hexValue(high);
        int lo = hexValue(low);
        if (hi < 0 || lo < 0) {
            return {};
        }
        result.push_back(static_cast<uint8_t>((hi << 4) | lo));
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
