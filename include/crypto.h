#ifndef CRYPTO_H
#define CRYPTO_H

#include "relic.h"
#include <secp256k1.h>
#include <sodium.h>
#include <paillier.h>
#include <dilithium/ref/sign.h>
#include <libshamir.h>

bool generate_keypair(std::vector<unsigned char>& public_key, std::vector<unsigned char>& private_key);
bool sign_relic(const Relic& relic, const std::vector<unsigned char>& private_key, std::vector<unsigned char>& signature);
bool sign_relic_dilithium(const Relic& relic, const std::vector<unsigned char>& private_key, std::vector<unsigned char>& signature);
bool verify_relic_dilithium(const Relic& relic, const std::vector<unsigned char>& public_key);
bool encrypt_private_key(const std::vector<unsigned char>& private_key, const std::string& passphrase,
                        std::vector<unsigned char>& encrypted_key, std::vector<unsigned char>& salt);
bool decrypt_private_key(const std::vector<unsigned char>& encrypted_key, const std::string& passphrase,
                        const std::vector<unsigned char>& salt, std::vector<unsigned char>& private_key);
bool perform_proof_of_work();
bool perform_trusted_nonce(const std::string& trusted_key);
bool acquire_rate_limit(const std::string& trusted_key = "");
std::vector<unsigned char> trusted_authority_key();

#endif