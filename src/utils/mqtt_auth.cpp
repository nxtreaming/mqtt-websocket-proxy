#include "utils/mqtt_auth.h"
#include "utils/logger.h"

#include <sstream>
#include <algorithm>
#include <cctype>

namespace xiaozhi {
namespace auth {

// MAC address regular expression (JavaScript version: /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/)
const std::regex MqttAuthenticator::mac_address_regex_(R"(^[0-9a-f]{2}(:[0-9a-f]{2}){5}$)");

MqttCredentials MqttAuthenticator::ValidateCredentials(const std::string& client_id,
                                                     const std::string& username,
                                                     const std::string& password) {
    MqttCredentials result;
    
    LOG_DEBUG("Validating MQTT credentials: client_id=" + client_id + ", username=" + username);
    
    // Parse client ID
    std::string group_id, mac_address, uuid;
    if (!ParseClientId(client_id, group_id, mac_address, uuid)) {
        LOG_WARN("Invalid client ID format: " + client_id);
        return result; // is_valid = false
    }

    // Validate MAC address format
    if (!IsValidMacAddress(mac_address)) {
        LOG_WARN("Invalid MAC address format: " + mac_address);
        return result; // is_valid = false
    }
    
    // Validate user data
    std::string user_data = ValidateUserData(client_id, username, password);
    if (user_data.empty()) {
        LOG_WARN("Invalid user data for client: " + client_id);
        return result; // is_valid = false
    }
    
    // Generate reply topic
    std::string reply_to_topic = GenerateReplyTopic(mac_address);
    
    // All validations passed, populate result
    result.is_valid = true;
    result.group_id = group_id;
    result.mac_address = mac_address;
    result.uuid = uuid;
    result.user_data = user_data;
    result.reply_to_topic = reply_to_topic;
    
    LOG_INFO("Authentication successful for client: " + client_id);
    LOG_DEBUG("Group ID: " + group_id + ", MAC: " + mac_address + 
             (uuid.empty() ? "" : ", UUID: " + uuid));
    
    return result;
}

bool MqttAuthenticator::IsValidMacAddress(const std::string& mac_address) {
    // Convert to lowercase for regex matching
    std::string mac_lower = mac_address;
    std::transform(mac_lower.begin(), mac_lower.end(), mac_lower.begin(), 
                  [](unsigned char c) { return std::tolower(c); });
                  
    return std::regex_match(mac_lower, mac_address_regex_);
}

bool MqttAuthenticator::ParseClientId(const std::string& client_id,
                                    std::string& group_id,
                                    std::string& mac_address,
                                    std::string& uuid) {
    // Clear output parameters
    group_id.clear();
    mac_address.clear();
    uuid.clear();
    
    // Check for empty client ID
    if (client_id.empty()) {
        LOG_WARN("Empty client ID");
        return false;
    }
    
    // JavaScript version uses "@@@" as separator
    // Example: "GID_xxx@@@mac_address@@@uuid"
    const std::string separator = "@@@";
    
    // Split client ID into parts
    std::vector<std::string> parts;
    size_t start = 0;
    size_t end = client_id.find(separator);
    
    while (end != std::string::npos) {
        parts.push_back(client_id.substr(start, end - start));
        start = end + separator.length();
        end = client_id.find(separator, start);
    }
    
    // Add the last part
    if (start < client_id.length()) {
        parts.push_back(client_id.substr(start));
    }
    
    // Check if we have at least 2 parts (group_id and mac_address)
    if (parts.size() < 2) {
        LOG_WARN("Invalid client ID format (missing parts): " + client_id);
        return false;
    }
    
    // Extract group ID (first part)
    group_id = parts[0];
    if (group_id.empty()) {
        LOG_WARN("Empty group ID in client ID: " + client_id);
        return false;
    }
    
    // Extract MAC address (second part)
    mac_address = parts[1];
    if (mac_address.empty()) {
        LOG_WARN("Empty MAC address in client ID: " + client_id);
        return false;
    }
    
    // Extract UUID if present (third part)
    if (parts.size() >= 3) {
        uuid = parts[2];
    }
    
    // Convert MAC address format if needed (xx_xx_xx_xx_xx_xx -> xx:xx:xx:xx:xx:xx)
    // JavaScript version: macAddress = macAddress.replace(/_/g, ':')
    if (mac_address.find('_') != std::string::npos) {
        mac_address = ConvertMacAddressFormat(mac_address);
    }
    
    // JavaScript version also converts MAC address to lowercase
    std::transform(mac_address.begin(), mac_address.end(), mac_address.begin(),
                  [](unsigned char c) { return std::tolower(c); });
    
    LOG_DEBUG("Parsed client ID: group_id=" + group_id + ", mac=" + mac_address + 
             (uuid.empty() ? "" : ", uuid=" + uuid));
    
    return true;
}

std::string MqttAuthenticator::GenerateReplyTopic(const std::string& mac_address_part) {
    return "device/" + mac_address_part + "/reply";
}

std::string MqttAuthenticator::ConvertMacAddressFormat(const std::string& mac_with_underscores) {
    std::string result = mac_with_underscores;
    std::replace(result.begin(), result.end(), '_', ':');
    return result;
}

std::string MqttAuthenticator::ValidateUserData(const std::string& client_id,
                                               const std::string& username,
                                               const std::string& password) {
    (void)client_id;
    (void)password;
    // Simple validation for now - just check if username is not empty
    // In a real implementation, this would validate against a database or other authentication system
    if (username.empty()) {
        return "";
    }
    
    // For demonstration purposes, we're just returning the username as the user data
    // In a real implementation, this might return a token, user profile, or other data
    return username;
    
    // Example of more complex validation logic:
    /*
    // Check if username matches expected format
    if (!std::regex_match(username, username_regex_)) {
        LOG_WARN("Invalid username format: " + username);
        return "";
    }
    
    // Check if password is valid
    if (password.empty() || password.length() < 8) {
        LOG_WARN("Invalid password for user: " + username);
        return "";
    }
    
    // In a real implementation, we might check against a database:
    UserRecord user = database_->GetUser(username);
    if (!user.IsValid() || !user.VerifyPassword(password)) {
        LOG_WARN("Authentication failed for user: " + username);
        return "";
    }
    
    // Return user data
    return user.GetUserData();
    */
}

} // namespace auth
} // namespace xiaozhi
