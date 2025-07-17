#include "relic/relic.h"
#include "relic/merkle.h"
#include "relic/wallet.h"
#include "relic/crypto.h"
#include "relic/smart_contract.h"
#include "relic/profile.h"
#include <iostream>
#include <fstream>
#include <sys/file.h>
#include <nfc/nfc.h>
#include <qrencode.h>
#include <uuid/uuid.h>
#include <chrono>
#include <iomanip>

static MerkleBurnList burn_list;

std::string get_current_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
    std::time_t time = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::gmtime(&time), "%Y-%m-%dT%H:%M:%S") << '.' << std::setfill('0') << std::setw(3) << ms.count() << "+01:00";
    return ss.str();
}

std::string generate_uuid() {
    uuid_t uuid;
    uuid_generate_random(uuid);
    char uuid_str[37];
    uuid_unparse_lower(uuid, uuid_str);
    return std::string(uuid_str);
}

bool sanitize_input(const std::string& input, bool is_file) {
    if (input.empty() || input.length() > MAX_INPUT_LENGTH) {
        log_audit_event("Invalid input length: " + input);
        return false;
    }
    if (is_file) {
        for (char c : input) {
            if (c == '/' || c == '\\' || c == ':' || c == '*') {
                log_audit_event("Invalid file path character: " + input);
                return false;
            }
        }
    }
    return true;
}

bool validate_serial(const std::string& serial) {
    if (!sanitize_input(serial) || serial.length() < 5 || serial.substr(0, 4) != "RLX-") {
        log_audit_event("Invalid serial format: " + serial);
        return false;
    }
    try {
        std::stoi(serial.substr(4));
        return true;
    } catch (...) {
        log_audit_event("Invalid serial number: " + serial);
        return false;
    }
}

std::string generate_new_serial() {
    static uint64_t counter = 0;
    while (true) {
        std::string serial = "RLX-" + std::to_string(++counter);
        if (!burn_list.is_mint_key_used(serial)) return serial;
        if (counter >= RELIC_MAX_SUPPLY) {
            log_audit_event("Max supply reached");
            throw std::runtime_error("Max supply reached");
        }
    }
}

std::string generate_referral_mint_key(const std::string& referrer_serial) {
    return "REF-" + referrer_serial + "-" + get_current_timestamp();
}

void log_audit_event(const std::string& event) {
    int fd = open("relic_audit.log", O_WRONLY | O_APPEND | O_CREAT, 0600);
    if (fd == -1) return;
    flock(fd, LOCK_EX);
    std::ofstream out("relic_audit.log", std::ios::app);
    out << get_current_timestamp() << ": " << event << "\n";
    out.close();
    flock(fd, LOCK_UN);
    close(fd);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: relic <command> [args]\nCommands: mint, transfer, verify, merge_burn_list, generate_qr, nfc_transfer, nfc_receive, scarcity_proof, backup_key, recover_key, referral\n";
        return 1;
    }

    if (!init_relic_system()) {
        std::cerr << "Failed to initialize Relic system\n";
        log_audit_event("System initialization failed");
        return 1;
    }

    std::string command = argv[1];
    try {
        if (command == "mint") {
            if (argc != 5 && argc != 7) throw std::invalid_argument("Usage: relic mint <serial> <mint_key> <passphrase> [--trusted-cert <cert_file>]");
            std::string serial = argv[2], mint_key = argv[3], passphrase = argv[4];
            std::string cert_file = (argc == 7 && std::string(argv[5]) == "--trusted-cert") ? argv[6] : "";
            if (!sanitize_input(serial) || !sanitize_input(mint_key) || !sanitize_input(passphrase) || (!cert_file.empty() && !sanitize_input(cert_file, true))) {
                throw std::invalid_argument("Invalid input");
            }
            if (!validate_serial(serial)) throw std::invalid_argument("Invalid serial");
            if (!acquire_rate_limit(cert_file)) throw std::runtime_error("Rate limit exceeded");
            Relic relic;
            std::vector<unsigned char> private_key;
            if (!create_relic(serial, get_current_timestamp(), mint_key, passphrase, relic, private_key)) {
                throw std::runtime_error("Failed to mint relic");
            }
            if (!store_relic_to_wallet(relic)) throw std::runtime_error("Failed to store relic");
            std::ofstream out(relic.serial + ".rlx");
            out << nlohmann::json(relic).dump();
            out.close();
            std::ofstream priv_out(relic.serial + ".key");
            priv_out << to_hex(private_key);
            priv_out.close();
            std::cout << "Minted relic: " << relic.serial << "\n";
            log_audit_event("Minted relic: serial=" + relic.serial);
        } else if (command == "transfer") {
            if (argc != 5 && argc != 7) throw std::invalid_argument("Usage: relic transfer <relic_file> <new_owner_pubkey> <passphrase> [--trusted-cert <cert_file>]");
            std::string relic_file = argv[2], new_owner_pubkey = argv[3], passphrase = argv[4];
            std::string cert_file = (argc == 7 && std::string(argv[5]) == "--trusted-cert") ? argv[6] : "";
            if (!sanitize_input(relic_file, true) || !sanitize_input(new_owner_pubkey) || !sanitize_input(passphrase) || (!cert_file.empty() && !sanitize_input(cert_file, true))) {
                throw std::invalid_argument("Invalid input");
            }
            if (!acquire_rate_limit(cert_file)) throw std::runtime_error("Rate limit exceeded");
            std::ifstream in(relic_file);
            nlohmann::json j;
            in >> j;
            in.close();
            Relic relic = j.get<Relic>();
            if (!verify_relic(relic)) throw std::runtime_error("Invalid relic");
            std::ifstream key_in(relic.serial + ".key");
            std::string key_hex;
            key_in >> key_hex;
            key_in.close();
            std::vector<unsigned char> private_key = from_hex(key_hex);
            Relic new_relic;
            std::vector<unsigned char> new_private_key;
            if (!transfer_relic(relic, new_owner_pubkey, get_current_timestamp(), private_key, true, new_relic, new_private_key)) {
                throw std::runtime_error("Failed to transfer relic");
            }
            if (!store_relic_to_wallet(new_relic)) throw std::runtime_error("Failed to store transferred relic");
            std::ofstream out(new_relic.serial + ".rlx");
            out << nlohmann::json(new_relic).dump();
            out.close();
            std::ofstream priv_out(new_relic.serial + ".key");
            priv_out << to_hex(new_private_key);
            priv_out.close();
            std::cout << "Transferred relic: " << new_relic.serial << "\n";
            log_audit_event("Transferred relic: serial=" + new_relic.serial);
        } else if (command == "verify") {
            if (argc != 3) throw std::invalid_argument("Usage: relic verify <relic_file>");
            std::string relic_file = argv[2];
            if (!sanitize_input(relic_file, true)) throw std::invalid_argument("Invalid input");
            std::ifstream in(relic_file);
            nlohmann::json j;
            in >> j;
            in.close();
            Relic relic = j.get<Relic>();
            if (!verify_relic(relic)) throw std::runtime_error("Relic verification failed");
            std::cout << "Relic verified: " << relic.serial << "\n";
            log_audit_event("Verified relic: serial=" + relic.serial);
        } else if (command == "merge_burn_list") {
            if (argc != 3) throw std::invalid_argument("Usage: relic merge_burn_list <other_burn_list_file>");
            std::string other_file = argv[2];
            if (!sanitize_input(other_file, true)) throw std::invalid_argument("Invalid input");
            if (!burn_list.merge_burn_list_incremental(other_file)) throw std::runtime_error("Failed to merge burn list");
            std::cout << "Burn list merged successfully\n";
            log_audit_event("Merged burn list: file=" + other_file);
        } else if (command == "generate_qr") {
            if (argc != 3) throw std::invalid_argument("Usage: relic generate_qr <relic_file>");
            std::string relic_file = argv[2];
            if (!sanitize_input(relic_file, true)) throw std::invalid_argument("Invalid input");
            std::ifstream in(relic_file);
            nlohmann::json j;
            in >> j;
            in.close();
            Relic relic = j.get<Relic>();
            std::string qr_data = generate_qr_code(relic);
            if (qr_data.empty()) throw std::runtime_error("Failed to generate QR code");
            std::cout << "QR Code: " << qr_data << "\n";
            log_audit_event("Generated QR code: serial=" + relic.serial);
        } else if (command == "nfc_transfer") {
            if (argc != 4) throw std::invalid_argument("Usage: relic nfc_transfer <relic_file> <new_owner_pubkey>");
            std::string relic_file = argv[2], new_owner_pubkey = argv[3];
            if (!sanitize_input(relic_file, true) || !sanitize_input(new_owner_pubkey)) throw std::invalid_argument("Invalid input");
            std::ifstream in(relic_file);
            nlohmann::json j;
            in >> j;
            in.close();
            Relic relic = j.get<Relic>();
            nfc_device* device = nfc_open(nullptr);
            if (!device) throw std::runtime_error("Failed to open NFC device");
            if (!transfer_relic_nfc(relic, new_owner_pubkey, device)) {
                nfc_close(device);
                throw std::runtime_error("NFC transfer failed");
            }
            nfc_close(device);
            std::cout << "Relic transferred via NFC: " << relic.serial << "\n";
            log_audit_event("NFC transfer: serial=" + relic.serial);
        } else if (command == "nfc_receive") {
            if (argc != 2) throw std::invalid_argument("Usage: relic nfc_receive");
            nfc_device* device = nfc_open(nullptr);
            if (!device) throw std::runtime_error("Failed to open NFC device");
            Relic relic;
            if (!receive_relic_nfc(device, relic)) {
                nfc_close(device);
                throw std::runtime_error("NFC receive failed");
            }
            nfc_close(device);
            std::cout << "Received relic via NFC: " << relic.serial << "\n";
            log_audit_event("Received NFC relic: serial=" + relic.serial);
        } else if (command == "scarcity_proof") {
            if (argc != 2) throw std::invalid_argument("Usage: relic scarcity_proof");
            std::vector<unsigned char> proof;
            if (!generate_scarcity_proof(proof)) throw std::runtime_error("Failed to generate scarcity proof");
            std::cout << "Scarcity proof: " << to_hex(proof) << "\n";
            log_audit_event("Generated scarcity proof");
        } else if (command == "backup_key") {
            if (argc != 5) throw std::invalid_argument("Usage: relic backup_key <key_file> <n> <k>");
            std::string key_file = argv[2];
            int n = std::stoi(argv[3]), k = std::stoi(argv[4]);
            if (!sanitize_input(key_file, true) || n < k || n < 1 || k < 1) throw std::invalid_argument("Invalid input");
            std::ifstream key_in(key_file);
            std::string key_hex;
            key_in >> key_hex;
            key_in.close();
            std::vector<unsigned char> private_key = from_hex(key_hex);
            std::vector<std::vector<unsigned char>> shares;
            if (!backup_private_key(private_key, n, k, shares)) throw std::runtime_error("Failed to backup key");
            for (size_t i = 0; i < shares.size(); ++i) {
                std::ofstream out("share_" + std::to_string(i) + ".key");
                out << to_hex(shares[i]);
                out.close();
            }
            std::cout << "Key backed up into " << n << " shares\n";
            log_audit_event("Backed up key: file=" + key_file);
        } else if (command == "recover_key") {
            if (argc < 3) throw std::invalid_argument("Usage: relic recover_key <share_file1> <share_file2> ...");
            std::vector<std::vector<unsigned char>> shares;
            for (int i = 2; i < argc; ++i) {
                if (!sanitize_input(argv[i], true)) throw std::invalid_argument("Invalid input");
                std::ifstream in(argv[i]);
                std::string hex;
                in >> hex;
                in.close();
                shares.push_back(from_hex(hex));
            }
            std::vector<unsigned char> private_key;
            if (!recover_private_key(shares, private_key)) throw std::runtime_error("Failed to recover key");
            std::ofstream out("recovered.key");
            out << to_hex(private_key);
            out.close();
            std::cout << "Key recovered\n";
            log_audit_event("Recovered key");
        } else if (command == "referral") {
            if (argc != 4) throw std::invalid_argument("Usage: relic referral <referrer_serial> <new_user_pubkey>");
            std::string referrer_serial = argv[2], new_user_pubkey = argv[3];
            if (!sanitize_input(referrer_serial) || !sanitize_input(new_user_pubkey)) throw std::invalid_argument("Invalid input");
            Relic referral_relic;
            if (!issue_referral_relic(referrer_serial, new_user_pubkey, referral_relic)) {
                throw std::runtime_error("Failed to issue referral relic");
            }
            if (!store_relic_to_wallet(referral_relic)) throw std::runtime_error("Failed to store referral relic");
            std::ofstream out(referral_relic.serial + ".rlx");
            out << nlohmann::json(referral_relic).dump();
            out.close();
            std::cout << "Referral relic issued: " << referral_relic.serial << "\n";
            log_audit_event("Issued referral relic: serial=" + referral_relic.serial);
            UserProfile profile;
            if (!update_user_profile(new_user_pubkey, "referral", profile)) {
                throw std::runtime_error("Failed to update user profile");
            }
        } else {
            throw std::invalid_argument("Unknown command: " + command);
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        log_audit_event("Command failed: " + command + ", error=" + e.what());
        return 1;
    }
    return 0;
}