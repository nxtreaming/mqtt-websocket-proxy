#pragma once

#include <string>
#include <vector>
#include <regex>

namespace xiaozhi {
namespace auth {

/**
 * @brief MQTT client authentication result
 */
struct MqttCredentials {
    bool is_valid = false;
    std::string group_id;
    std::string mac_address;
    std::string uuid;
    std::string user_data;
    std::string reply_to_topic;
};

/**
 * @brief MQTT authentication utility class
 *
 * Compatible with JavaScript version authentication logic:
 * - Supports GID_test@@@mac_address@@@uuid format
 * - Supports GID_test@@@mac_address format
 * - MAC address format validation
 * - User data validation
 */
class MqttAuthenticator {
public:
    /**
     * @brief Validate MQTT client credentials
     * 
     * @param client_id MQTT client ID (format: GID_xxx@@@mac_address[@@@uuid])
     * @param username MQTT username
     * @param password MQTT password
     * @return MqttCredentials Authentication result with parsed data
     */
    static MqttCredentials ValidateCredentials(const std::string& client_id,
                                              const std::string& username,
                                              const std::string& password);
    
    /**
     * @brief Check if MAC address format is valid
     * 
     * @param mac_address MAC address to validate (format: xx:xx:xx:xx:xx:xx)
     * @return true If MAC address format is valid
     * @return false If MAC address format is invalid
     */
    static bool IsValidMacAddress(const std::string& mac_address);
    
    /**
     * @brief Parse client ID into components
     * 
     * @param client_id MQTT client ID (format: GID_xxx@@@mac_address[@@@uuid])
     * @param group_id Output parameter for group ID
     * @param mac_address Output parameter for MAC address
     * @param uuid Output parameter for UUID (if present)
     * @return true If parsing succeeded
     * @return false If parsing failed
     */
    static bool ParseClientId(const std::string& client_id,
                             std::string& group_id,
                             std::string& mac_address,
                             std::string& uuid);
    
    /**
     * @brief Generate reply topic for a client
     * 
     * @param mac_address_part MAC address part from client ID
     * @return std::string Reply topic
     */
    static std::string GenerateReplyTopic(const std::string& mac_address_part);
    
    /**
     * @brief Convert MAC address format from xx_xx_xx_xx_xx_xx to xx:xx:xx:xx:xx:xx
     * 
     * @param mac_with_underscores MAC address with underscores
     * @return std::string MAC address with colons
     */
    static std::string ConvertMacAddressFormat(const std::string& mac_with_underscores);
    
    /**
     * @brief Validate user data from MQTT credentials
     * 
     * @param client_id MQTT client ID
     * @param username MQTT username
     * @param password MQTT password
     * @return std::string Validated user data or empty string if invalid
     */
    static std::string ValidateUserData(const std::string& client_id,
                                       const std::string& username,
                                       const std::string& password);

private:
    // Regular expression for MAC address validation
    static const std::regex mac_address_regex_;
};

} // namespace auth
} // namespace xiaozhi
