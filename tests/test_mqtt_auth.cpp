#include "utils/mqtt_auth.h"
#include "utils/logger.h"
#include "common/error_codes.h"

#include <iostream>
#include <cassert>

using namespace xiaozhi;
using namespace xiaozhi::auth;

void TestMacAddressValidation() {
    std::cout << "Testing MAC address validation..." << std::endl;
    
    // Valid MAC addresses
    assert(MqttAuthenticator::IsValidMacAddress("00:11:22:33:44:55"));
    assert(MqttAuthenticator::IsValidMacAddress("aa:bb:cc:dd:ee:ff"));
    assert(MqttAuthenticator::IsValidMacAddress("12:34:56:78:9a:bc"));
    
    // Invalid MAC addresses
    assert(!MqttAuthenticator::IsValidMacAddress("00:11:22:33:44"));     // Too short
    assert(!MqttAuthenticator::IsValidMacAddress("00:11:22:33:44:55:66")); // Too long
    assert(!MqttAuthenticator::IsValidMacAddress("00-11-22-33-44-55"));   // Wrong separator
    assert(!MqttAuthenticator::IsValidMacAddress("gg:11:22:33:44:55"));   // Invalid hex
    assert(!MqttAuthenticator::IsValidMacAddress(""));                     // Empty
    
    std::cout << "MAC address validation test passed" << std::endl;
}

void TestClientIdParsing() {
    std::cout << "Testing client ID parsing..." << std::endl;
    
    std::string group_id, mac_address, uuid;
    
    // Test 3-part format: GID_test@@@mac_address@@@uuid
    bool result = MqttAuthenticator::ParseClientId("GID_test@@@00_11_22_33_44_55@@@uuid123", 
                                                  group_id, mac_address, uuid);
    assert(result);
    assert(group_id == "GID_test");
    assert(mac_address == "00:11:22:33:44:55");
    assert(uuid == "uuid123");
    
    // Test 2-part format: GID_test@@@mac_address
    result = MqttAuthenticator::ParseClientId("GID_production@@@aa_bb_cc_dd_ee_ff", 
                                            group_id, mac_address, uuid);
    assert(result);
    assert(group_id == "GID_production");
    assert(mac_address == "aa:bb:cc:dd:ee:ff");
    assert(uuid == "");
    
    // Test invalid formats
    result = MqttAuthenticator::ParseClientId("invalid_format", group_id, mac_address, uuid);
    assert(!result);
    
    result = MqttAuthenticator::ParseClientId("", group_id, mac_address, uuid);
    assert(!result);
    
    std::cout << "Client ID parsing test passed" << std::endl;
}

void TestMacAddressConversion() {
    std::cout << "Testing MAC address format conversion..." << std::endl;
    
    // Test underscore to colon conversion
    assert(MqttAuthenticator::ConvertMacAddressFormat("00_11_22_33_44_55") == "00:11:22:33:44:55");
    assert(MqttAuthenticator::ConvertMacAddressFormat("aa_bb_cc_dd_ee_ff") == "aa:bb:cc:dd:ee:ff");
    assert(MqttAuthenticator::ConvertMacAddressFormat("12_34_56_78_9a_bc") == "12:34:56:78:9a:bc");
    
    // Test already colon format (should remain unchanged)
    assert(MqttAuthenticator::ConvertMacAddressFormat("00:11:22:33:44:55") == "00:11:22:33:44:55");
    
    std::cout << "MAC address conversion test passed" << std::endl;
}

void TestReplyTopicGeneration() {
    std::cout << "Testing reply topic generation..." << std::endl;
    
    // Test reply topic generation (JavaScript: `devices/p2p/${parts[1]}`)
    assert(MqttAuthenticator::GenerateReplyTopic("00_11_22_33_44_55") == "devices/p2p/00_11_22_33_44_55");
    assert(MqttAuthenticator::GenerateReplyTopic("aa_bb_cc_dd_ee_ff") == "devices/p2p/aa_bb_cc_dd_ee_ff");
    
    std::cout << "Reply topic generation test passed" << std::endl;
}

void TestCredentialValidation() {
    std::cout << "Testing credential validation..." << std::endl;
    
    // Test valid credentials (3-part format)
    MqttCredentials creds = MqttAuthenticator::ValidateCredentials(
        "GID_test@@@00_11_22_33_44_55@@@uuid123",
        "test_user",
        "test_password"
    );
    
    assert(creds.is_valid);
    assert(creds.group_id == "GID_test");
    assert(creds.mac_address == "00:11:22:33:44:55");
    assert(creds.uuid == "uuid123");
    assert(creds.reply_to_topic == "devices/p2p/00_11_22_33_44_55");
    assert(!creds.user_data.empty());
    
    // Test valid credentials (2-part format)
    creds = MqttAuthenticator::ValidateCredentials(
        "GID_production@@@aa_bb_cc_dd_ee_ff",
        "prod_user",
        "prod_password"
    );
    
    assert(creds.is_valid);
    assert(creds.group_id == "GID_production");
    assert(creds.mac_address == "aa:bb:cc:dd:ee:ff");
    assert(creds.uuid == "");
    assert(creds.reply_to_topic == "devices/p2p/aa_bb_cc_dd_ee_ff");
    
    // Test invalid client ID format
    creds = MqttAuthenticator::ValidateCredentials(
        "invalid_format",
        "user",
        "password"
    );
    assert(!creds.is_valid);
    
    // Test invalid MAC address
    creds = MqttAuthenticator::ValidateCredentials(
        "GID_test@@@invalid_mac@@@uuid",
        "user",
        "password"
    );
    assert(!creds.is_valid);
    
    // Test empty credentials
    creds = MqttAuthenticator::ValidateCredentials("", "", "");
    assert(!creds.is_valid);
    
    std::cout << "Credential validation test passed" << std::endl;
}

void TestJavaScriptCompatibility() {
    std::cout << "Testing JavaScript compatibility..." << std::endl;
    
    // Test exact JavaScript format compatibility
    // JavaScript: const parts = this.clientId.split('@@@');
    // JavaScript: this.macAddress = parts[1].replace(/_/g, ':');
    // JavaScript: this.replyTo = `devices/p2p/${parts[1]}`;
    
    MqttCredentials creds = MqttAuthenticator::ValidateCredentials(
        "GID_xiaozhi@@@12_34_56_78_9a_bc@@@device_uuid_12345",
        "xiaozhi_user",
        "secure_password"
    );
    
    assert(creds.is_valid);
    assert(creds.group_id == "GID_xiaozhi");
    assert(creds.mac_address == "12:34:56:78:9a:bc");  // Converted from underscores
    assert(creds.uuid == "device_uuid_12345");
    assert(creds.reply_to_topic == "devices/p2p/12_34_56_78_9a_bc");  // Original format with underscores
    
    std::cout << "JavaScript compatibility test passed" << std::endl;
}

int main() {
    std::cout << "=== xiaozhi-mqtt-gateway MQTT Authentication Test ===" << std::endl;
    
    // Initialize logger
    Logger& logger = Logger::GetInstance();
    if (!logger.Initialize(LogLevel::DEBUG)) {
        std::cerr << "Failed to initialize logger" << std::endl;
        return 1;
    }
    
    try {
        TestMacAddressValidation();
        TestClientIdParsing();
        TestMacAddressConversion();
        TestReplyTopicGeneration();
        TestCredentialValidation();
        TestJavaScriptCompatibility();
        
        std::cout << std::endl;
        std::cout << "All MQTT Authentication Tests Passed!" << std::endl;
        std::cout << std::endl;
        std::cout << "Working Features:" << std::endl;
        std::cout << "  Client ID Parsing (GID@@@MAC@@@UUID format)" << std::endl;
        std::cout << "  MAC Address Validation (regex: ^[0-9a-f]{2}(:[0-9a-f]{2}){5}$)" << std::endl;
        std::cout << "  MAC Address Format Conversion (underscore ↔ colon)" << std::endl;
        std::cout << "  Reply Topic Generation (devices/p2p/MAC_ADDRESS)" << std::endl;
        std::cout << "  User Data Validation" << std::endl;
        std::cout << "  JavaScript Compatibility" << std::endl;
        std::cout << std::endl;
        std::cout << "MQTT authentication is now compatible with JavaScript version!" << std::endl;
        std::cout << std::endl;
        std::cout << "Supported Client ID Formats:" << std::endl;
        std::cout << "  GID_test@@@mac_address@@@uuid (3 parts)" << std::endl;
        std::cout << "  GID_test@@@mac_address (2 parts)" << std::endl;
        std::cout << "  MAC address format: 00_11_22_33_44_55 → 00:11:22:33:44:55" << std::endl;
        std::cout << "  Reply topic: devices/p2p/00_11_22_33_44_55" << std::endl;
        
        return 0;
        
    } catch (const std::exception& e) {
        std::cerr << "Test failed with exception: " << e.what() << std::endl;
        return 1;
    }
}
