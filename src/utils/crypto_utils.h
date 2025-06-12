#pragma once

#ifdef _WIN32
    #if defined(XIAOZHI_CRYPTO_STATIC)
        #define XIAOZHI_CRYPTO_API
    #elif defined(XIAOZHI_CRYPTO_EXPORTS)
        #define XIAOZHI_CRYPTO_API __declspec(dllexport)
    #else
        #define XIAOZHI_CRYPTO_API __declspec(dllimport)
    #endif
#else
    #define XIAOZHI_CRYPTO_API __attribute__((visibility("default")))
#endif

#include <vector>
#include <string>
#include <cstdint>

namespace xiaozhi {
namespace crypto {

/**
 * @brief AES-128-CTR encryption for audio data
 *
 * Compatible with JavaScript Node.js crypto implementation:
 * - Uses AES-128-CTR mode
 * - 16-byte key (crypto.randomBytes(16))
 * - UDP header as IV/nonce for each packet
 * - Compatible with crypto.createCipheriv('aes-128-ctr', key, header)
 */
class AudioCrypto {
public:
    /**
     * @brief Constructor
     */
    AudioCrypto();

    /**
     * @brief Destructor
     */
    ~AudioCrypto();

    /**
     * @brief Initialize with encryption key
     * @param key Encryption key (16 bytes for AES-128)
     * @return Error code, 0 indicates success
     */
    int Initialize(const std::vector<uint8_t>& key);

    /**
     * @brief Encrypt audio data using UDP header as IV
     * @param data Input audio data
     * @param header UDP header (16 bytes) used as IV
     * @param encrypted_data Output encrypted data
     * @return Error code, 0 indicates success
     */
    int Encrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& header, std::vector<uint8_t>& encrypted_data);

    /**
     * @brief Decrypt audio data using UDP header as IV
     * @param encrypted_data Input encrypted data
     * @param header UDP header (16 bytes) used as IV
     * @param data Output decrypted data
     * @return Error code, 0 indicates success
     */
    int Decrypt(const std::vector<uint8_t>& encrypted_data, const std::vector<uint8_t>& header, std::vector<uint8_t>& data);

    /**
     * @brief Generate random AES-128 key
     * @return Generated 16-byte key
     */
    static std::vector<uint8_t> GenerateKey();

    /**
     * @brief Check if crypto is initialized
     * @return true if initialized
     */
    bool IsInitialized() const { return initialized_; }

private:
    /**
     * @brief Perform AES-128-CTR encryption/decryption
     * @param data Input data
     * @param key AES key (16 bytes)
     * @param iv Initialization vector (16 bytes)
     * @param output Output data
     * @return Error code, 0 indicates success
     */
    int PerformAES128CTR(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key,
                        const std::vector<uint8_t>& iv, std::vector<uint8_t>& output);

private:
    bool initialized_;
    std::vector<uint8_t> key_;
};

/**
 * @brief UDP header generator for encryption IV
 *
 * Compatible with JavaScript implementation:
 * generateUdpHeader(length, timestamp, sequence)
 */
class UDPHeaderGenerator {
public:
    /**
     * @brief Generate UDP header (16 bytes) for use as encryption IV
     * @param connection_id Connection ID (4 bytes)
     * @param length Payload length (2 bytes)
     * @param timestamp Timestamp (4 bytes)
     * @param sequence Sequence number (4 bytes)
     * @param header Output header buffer (16 bytes)
     * @return Error code, 0 indicates success
     */
    static int GenerateHeader(uint32_t connection_id, uint16_t length, uint32_t timestamp,
                             uint32_t sequence, std::vector<uint8_t>& header);

    /**
     * @brief Parse UDP header
     * @param header Input header buffer (16 bytes)
     * @param connection_id Output connection ID
     * @param length Output payload length
     * @param timestamp Output timestamp
     * @param sequence Output sequence number
     * @return Error code, 0 indicates success
     */
    static int ParseHeader(const std::vector<uint8_t>& header, uint32_t& connection_id,
                          uint16_t& length, uint32_t& timestamp, uint32_t& sequence);

    /**
     * @brief Generate WebSocket audio packet format (JavaScript compatible)
     *
     * JavaScript format for WebSocket binary messages:
     * [unknown: 8 bytes][timestamp: 4u BE][opusLength: 4u BE][opus: opusLength bytes]
     *
     * @param opus_data Opus audio data
     * @param timestamp Timestamp
     * @param packet Output packet buffer
     * @return Error code, 0 indicates success
     */
    static int GenerateWebSocketAudioPacket(const std::vector<uint8_t>& opus_data,
                                          uint32_t timestamp,
                                          std::vector<uint8_t>& packet);

    /**
     * @brief Parse WebSocket audio packet format (JavaScript compatible)
     * @param packet Input packet buffer
     * @param opus_data Output Opus audio data
     * @param timestamp Output timestamp
     * @return Error code, 0 indicates success
     */
    static int ParseWebSocketAudioPacket(const std::vector<uint8_t>& packet,
                                       std::vector<uint8_t>& opus_data,
                                       uint32_t& timestamp);
};

/**
 * @brief Utility functions for audio encryption
 */
namespace utils {

/**
 * @brief Create encryption key from session ID
 * @param session_id Session ID
 * @return Encryption key
 */
std::vector<uint8_t> CreateKeyFromSessionId(const std::string& session_id);

/**
 * @brief Encode binary data to base64
 * @param data Input binary data
 * @return Base64 encoded string
 */
XIAOZHI_CRYPTO_API std::string EncodeBase64(const std::vector<uint8_t>& data);

/**
 * @brief Decode base64 string to binary data
 * @param base64_str Base64 encoded string
 * @return Decoded binary data
 */
XIAOZHI_CRYPTO_API std::vector<uint8_t> DecodeBase64(const std::string& base64_str);

} // namespace utils
} // namespace crypto
} // namespace xiaozhi
