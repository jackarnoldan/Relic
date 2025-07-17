#include "relic/crypto.h"
#include <openssl/sha.h>
#include <sodium.h>
#include <paillier.h>
#include <dilithium/ref/sign.h>
#include <libshamir.h>

bool generate_keypair(std::vector<unsigned char>& public_key, std::vector<unsigned char>& private_key) {
    private_key.resize(crypto_sign_dilithium_SECRETKEYBYTES + 32); // Dilithium + ECDSA
    public_key.resize(crypto_sign_dilithium_PUBLICKEYBYTES + 33);
    if (crypto_sign_dilithium_keypair(public_key.data(), private_key.data()) != 0) {
        log_audit_event("Failed to generate Dilithium keypair");
        return false;
    }
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    if (!crypto_randombytes_buf(private_key.data() + crypto_sign_dilithium_SECRETKEYBYTES, 32)) {
        log_audit_event("Failed to generate ECDSA private key");
        secp256k1_context_destroy(ctx);
        return false;
    }
    if (!secp256k1_ec_pubkey_create(ctx, (secp256k1_pubkey*)(public_key.data() + crypto_sign_dilithium_PUBLICKEYBYTES),
                                    private_key.data() + crypto_sign_dilithium_SECRETKEYBYTES)) {
        log_audit_event("Failed to generate ECDSA public key");
        secp256k1_context_destroy(ctx);
        return false;
    }
    secp256k1_context_destroy(ctx);
    log_audit_event("Generated keypair");
    return true;
}

bool sign_relic(const Relic& relic, const std::vector<unsigned char>& private_key, std::vector<unsigned char>& signature) {
    std::vector<unsigned char> message = relic_to_bytes(relic);
    signature.resize(70);
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    if (!secp256k1_ecdsa_sign(ctx, (secp256k1_ecdsa_signature*)signature.data(), message.data(),
                              private_key.data() + crypto_sign_dilithium_SECRETKEYBYTES, nullptr, nullptr)) {
        log_audit_event("Failed ECDSA signature: serial=" + relic.serial);
        secp256k1_context_destroy(ctx);
        return false;
    }
    secp256k1_context_destroy(ctx);
    log_audit_event("Signed relic with ECDSA: serial=" + relic.serial);
    return true;
}

bool sign_relic_dilithium(const Relic& relic, const std::vector<unsigned char>& private_key, std::vector<unsigned char>& signature) {
    std::vector<unsigned char> message = relic_to_bytes(relic);
    signature.resize(crypto_sign_dilithium_BYTES);
    if (crypto_sign_dilithium(signature.data(), nullptr, message.data(), message.size(), private_key.data()) != 0) {
        log_audit_event("Failed Dilithium signature: serial=" + relic.serial);
        return false;
    }
    log_audit_event("Signed relic with Dilithium: serial=" + relic.serial);
    return true;
}

bool verify_relic_dilithium(const Relic& relic, const std::vector<unsigned char>& public_key) {
    std::vector<unsigned char> message = relic_to_bytes(relic);
    if (crypto_sign_dilithium_open(nullptr, nullptr, message.data(), message.size(), public_key.data()) != 0) {
        log_audit_event("Dilithium verification failed: serial=" + relic.serial);
        return false;
    }
    log_audit_event("Verified relic with Dilithium: serial=" + relic.serial);
    return true;
}

bool encrypt_private_key(const std::vector<unsigned char>& private_key, const std::string& passphrase,
                        std::vector<unsigned char>& encrypted_key, std::vector<unsigned char>& salt) {
    salt.resize(crypto_pwhash_SALTBYTES);