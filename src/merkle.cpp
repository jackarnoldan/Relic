#include "relic/merkle.h"
#include <openssl/sha.h>
#include <bloom/bloom_filter.hpp>
#include <fstream>
#include <sys/file.h>

MerkleBurnList::MerkleBurnList() : root_(std::make_shared<MerkleNode>()) {
    bloom_ = std::make_unique<bloom_filter>(RELIC_BLOOM_CAPACITY, RELIC_BLOOM_FPR);
}

bool MerkleBurnList::add_mint_key(const std::string& mint_key) {
    if (!sanitize_input(mint_key)) {
        log_audit_event("Invalid mint key: " + mint_key);
        return false;
    }
    if (bloom_->contains(mint_key)) {
        log_audit_event("Mint key already in bloom filter: " + mint_key);
        return false;
    }
    unsigned char hash[SHA256_DIGEST_LENGTH];
    if (crypto_hash_sha256(hash, (unsigned char*)mint_key.c_str(), mint_key.size()) != 0) {
        log_audit_event("Failed to hash mint key: " + mint_key);
        return false;
    }
    auto node = std::make_shared<MerkleNode>();
    node->hash = std::vector<unsigned char>(hash, hash + SHA256_DIGEST_LENGTH);
    node->mint_key = mint_key;
    leaves_.push_back(node);
    bloom_->add(mint_key);
    rebuild_tree();
    if (!save_burn_list()) {
        log_audit_event("Failed to save burn list after adding: " + mint_key);
        return false;
    }
    log_audit_event("Added mint key to burn list: " + mint_key);
    return true;
}

bool MerkleBurnList::is_mint_key_used(const std::string& mint_key) {
    bool result = bloom_->contains(mint_key);
    log_audit_event("Checked mint key: " + mint_key + ", used=" + (result ? "true" : "false"));
    return result;
}

bool MerkleBurnList::merge_burn_list(const MerkleBurnList& other) {
    std::vector<std::string> new_keys;
    for (const auto& leaf : other.leaves_) {
        if (!bloom_->contains(leaf->mint_key)) {
            new_keys.push_back(leaf->mint_key);
        }
    }
    for (const auto& key : new_keys) {
        if (!add_mint_key(key)) {
            log_audit_event("Failed to merge mint key: " + key);
            return false;
        }
    }
    if (!verify_root(other.root_->hash)) {
        log_audit_event("Root hash verification failed during merge");
        return false;
    }
    log_audit_event("Merged burn list with " + std::to_string(new_keys.size()) + " new keys");
    return true;
}

bool MerkleBurnList::merge_burn_list_incremental(const std::string& other_file, size_t batch_size) {
    MerkleBurnList other;
    if (!other.load_burn_list(other_file)) {
        log_audit_event("Failed to load burn list for merge: " + other_file);
        return false;
    }
    size_t offset = 0;
    while (offset < other.leaves_.size()) {
        std::vector<std::string> batch;
        for (size_t i = offset; i < std::min(offset + batch_size, other.leaves_.size()); ++i) {
            if (!bloom_->contains(other.leaves_[i]->mint_key)) {
                batch.push_back(other.leaves_[i]->mint_key);
            }
        }
        for (const auto& key : batch) {
            if (!add_mint_key(key)) {
                log_audit_event("Failed to merge mint key incrementally: " + key);
                return false;
            }
        }
        offset += batch_size;
        if (!save_burn_list()) {
            log_audit_event("Failed to save burn list during incremental merge");
            return false;
        }
    }
    if (!verify_root(other.root_->hash)) {
        log_audit_event("Root hash verification failed during incremental merge");
        return false;
    }
    log_audit_event("Incrementally merged burn list: " + other_file);
    return true;
}

bool MerkleBurnList::save_burn_list() {
    int fd = open("relic_burn_list.merkle", O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd == -1) {
        log_audit_event("Failed to open burn list file for saving");
        return false;
    }
    std::ofstream out("relic_burn_list.merkle", std::ios::binary);
    nlohmann::json j;
    j["root_hash"] = to_hex(root_->hash);
    j["leaves"] = nlohmann::json::array();
    for (const auto& leaf : leaves_) {
        j["leaves"].push_back({{"mint_key", leaf->mint_key}, {"hash", to_hex(leaf->hash)}});
    }
    out << j.dump();
    out.close();
    flock(fd, LOCK_UN);
    close(fd);
    log_audit_event("Saved burn list");
    return true;
}

bool MerkleBurnList::load_burn_list(const std::string& file) {
    std::string filename = file.empty() ? "relic_burn_list.merkle" : file;
    std::ifstream in(filename, std::ios::binary);
    if (!in) {
        log_audit_event("Failed to open burn list file: " + filename);
        return false;
    }
    nlohmann::json j;
    try {
        in >> j;
    } catch (const std::exception& e) {
        log_audit_event("Failed to parse burn list JSON: " + std::string(e.what()));
        in.close();
        return false;
    }
    in.close();
    leaves_.clear();
    bloom_ = std::make_unique<bloom_filter>(RELIC_BLOOM_CAPACITY, RELIC_BLOOM_FPR);
    for (const auto& leaf : j["leaves"]) {
        auto node = std::make_shared<MerkleNode>();
        node->mint_key = leaf["mint_key"].get<std::string>();
        node->hash = from_hex(leaf["hash"].get<std::string>());
        leaves_.push_back(node);
        bloom_->add(node->mint_key);
    }
    rebuild_tree();
    if (!verify_root(from_hex(j["root_hash"].get<std::string>()))) {
        log_audit_event("Root hash verification failed on load");
        return false;
    }
    log_audit_event("Loaded burn list from: " + filename);
    return true;
}

bool MerkleBurnList::verify_root(const std::vector<unsigned char>& expected_root) {
    bool result = root_->hash == expected_root;
    log_audit_event("Root hash verification " + std::string(result ? "succeeded" : "failed"));
    return result;
}

std::string MerkleBurnList::generate_burn_list_qr(size_t batch_size) {
    nlohmann::json j;
    j["root_hash"] = to_hex(root_->hash);
    j["leaves"] = nlohmann::json::array();
    for (size_t i = 0; i < std::min(batch_size, leaves_.size()); ++i) {
        j["leaves"].push_back({{"mint_key", leaves_[i]->mint_key}, {"hash", to_hex(leaves_[i]->hash)}});
    }
    QRcode* qr = QRcode_encodeString(j.dump().c_str(), 0, QR_ECLEVEL_H, QR_MODE_8, 1);
    if (!qr) {
        log_audit_event("Failed to generate burn list QR code");
        return "";
    }
    std::string qr_data(reinterpret_cast<char*>(qr->data), qr->width * qr->width);
    QRcode_free(qr);
    log_audit_event("Generated burn list QR code for " + std::to_string(std::min(batch_size, leaves_.size())) + " keys");
    return qr_data;
}

void MerkleBurnList::rebuild_tree() {
    std::vector<std::shared_ptr<MerkleNode>> current = leaves_;
    while (current.size() > 1) {
        std::vector<std::shared_ptr<MerkleNode>> next;
        for (size_t i = 0; i < current.size(); i += 2) {
            auto parent = std::make_shared<MerkleNode>();
            parent->left = current[i];
            parent->right = (i + 1 < current.size()) ? current[i + 1] : current[i];
            std::vector<unsigned char> combined(parent->left->hash);
            combined.insert(combined.end(), parent->right->hash.begin(), parent->right->hash.end());
            parent->hash.resize(SHA256_DIGEST_LENGTH);
            if (crypto_hash_sha256(parent->hash.data(), combined.data(), combined.size()) != 0) {
                log_audit_event("Failed to rebuild Merkle tree");
                throw std::runtime_error("Merkle tree rebuild failed");
            }
            next.push_back(parent);
        }
        current = next;
    }
    root_ = current.empty() ? std::make_shared<MerkleNode>() : current[0];
}