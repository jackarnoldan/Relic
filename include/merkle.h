#ifndef MERKLE_H
#define MERKLE_H

#include <vector>
#include <string>
#include <memory>
#include <bloom/bloom_filter.hpp>
#include "config.h"

struct MerkleNode {
    std::vector<unsigned char> hash; // SHA-256
    std::shared_ptr<MerkleNode> left, right;
    std::string mint_key; // Leaf nodes only
};

class MerkleBurnList {
public:
    MerkleBurnList();
    bool add_mint_key(const std::string& mint_key);
    bool is_mint_key_used(const std::string& mint_key);
    bool merge_burn_list(const MerkleBurnList& other);
    bool merge_burn_list_incremental(const std::string& other_file, size_t batch_size = 1000);
    bool save_burn_list();
    bool load_burn_list(const std::string& file = "");
    bool verify_root(const std::vector<unsigned char>& expected_root);
    std::string generate_burn_list_qr(size_t batch_size = 1000);
    size_t size() const { return leaves_.size(); }
private:
    std::shared_ptr<MerkleNode> root_;
    std::vector<std::shared_ptr<MerkleNode>> leaves_;
    std::unique_ptr<bloom_filter> bloom_;
    void rebuild_tree();
};

#endif