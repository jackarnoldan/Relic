#ifndef RELIC_H
#define RELIC_H

#include <string>
#include <vector>
#include <nlohmann/json.hpp>
#include "config.h"

struct Relic {
    std::string serial; // e.g., "RLX-00000001"
    std::string timestamp; // ISO 8601
    std::string transaction_id; // UUID
    std::vector<unsigned char> public_key; // ECDSA + Dilithium
    std::vector<unsigned char> hash_chain; // SHA-512
    std::vector<unsigned char> ecdsa_signature;
    std::vector<unsigned char> dilithium_signature;
    std::vector<std::vector<unsigned char>> multi_signatures; // m-of-n
    std::string smart_contract; // Lua script
};

struct BatchTransaction {
    Relic old_relic;
    std::string new_owner_pubkey;
    std::vector<unsigned char> private_key; // Added for batch processing
    bool use_burner;
};

struct UserProfile {
    std::string public_key;
    int referrals;
    int transactions;
    std::vector<std::string> badges;
};

bool init_relic_system();
bool create_relic(const std::string& serial, const std::string& timestamp, const std::string& mint_key,
                  const std::string& passphrase, Relic& relic, std::vector<unsigned char>& private_key);
bool create_multi_signature_relic(const std::string& serial, const std::string& timestamp, const std::string& mint_key,
                                 const std::vector<std::vector<unsigned char>>& private_keys, int m,
                                 Relic& relic, std::vector<unsigned char>& aggregated_private_key);
bool create_smart_contract_relic(const std::string& serial, const std::string& timestamp, const std::string& mint_key,
                                const std::string& passphrase, const std::string& contract, Relic& relic,
                                std::vector<unsigned char>& private_key);
bool transfer_relic(const Relic& relic, const std::string& new_owner_pubkey, const std::string& timestamp,
                    const std::vector<unsigned char>& private_key, bool use_burner, Relic& new_relic,
                    std::vector<unsigned char>& new_private_key);
bool batch_transfer_relics(const std::vector<BatchTransaction>& transactions);
bool verify_relic(const Relic& relic);
bool verify_multi_signature_relic(const Relic& relic, const std::vector<std::vector<unsigned char>>& public_keys, int m);
bool execute_smart_contract(const Relic& relic, const std::vector<unsigned char>& input, std::vector<unsigned char>& output);
bool encrypt_relic_homomorphic(const Relic& relic, const paillier_pubkey_t* pubkey, std::vector<unsigned char>& encrypted);
bool verify_relic_homomorphic(const std::vector<unsigned char>& encrypted, const paillier_pubkey_t* pubkey);
bool generate_scarcity_proof(std::vector<unsigned char>& proof);
bool backup_private_key(const std::vector<unsigned char>& private_key, int n, int k, std::vector<std::vector<unsigned char>>& shares);
bool recover_private_key(const std::vector<std::vector<unsigned char>>& shares, std::vector<unsigned char>& private_key);
bool issue_referral_relic(const std::string& referrer_serial, const std::string& new_user_pubkey, Relic& referral_relic);
bool update_user_profile(const std::string& pubkey, const std::string& action, UserProfile& profile);
std::string generate_qr_code(const Relic& relic);
bool verify_qr_code(const std::string& qr_data, Relic& relic);
bool transfer_relic_nfc(const Relic& relic, const std::string& new_owner_pubkey, nfc_device* device);
bool receive_relic_nfc(nfc_device* device, Relic& relic);
std::string generate_uuid();
std::string get_current_timestamp();
bool sanitize_input(const std::string& input, bool is_file = false);
bool validate_serial(const std::string& serial);
std::string generate_new_serial();
std::string generate_referral_mint_key(const std::string& referrer_serial);
void log_audit_event(const std::string& event);
std::string to_hex(const std::vector<unsigned char>& data);
std::vector<unsigned char> from_hex(const std::string& hex);

#endif