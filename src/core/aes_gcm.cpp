#include "aes_gcm.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>

namespace pqc {

    AesGcmKeys AesGcm::encrypt(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& key) {

        if(key.size() != 32) {

            throw std::runtime_error("Key must be 256 bits (32 bytes) for AES-256-GCM.");

        }

        AesGcmKeys keys;

        keys.init_vec.resize(12);

        if(RAND_bytes(keys.init_vec.data(), 12) != 1) {

            throw std::runtime_error("Failed to generate random initialization vector.");

        }

        keys.ciphertext.resize(plaintext.size());
        keys.auth_tag.resize(16);

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

        if(!ctx) {

            throw std::runtime_error("Failed to create EVP_CIPHER_CTX.");

        }

        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), keys.init_vec.data());

        int length = 0;

        EVP_EncryptUpdate(ctx, keys.ciphertext.data(), &length, plaintext.data(), plaintext.size());

        int final_length = 0;

        EVP_EncryptFinal_ex(ctx, keys.ciphertext.data() + length, &final_length);
        
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, keys.auth_tag.data());
        EVP_CIPHER_CTX_free(ctx);
        
        return keys;

    }

    std::vector<uint8_t> AesGcm::decrypt(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& key, const std::vector<uint8_t>& init_vec, const std::vector<uint8_t>& auth_tag) {

        if(key.size() != 32) {

            throw std::runtime_error("Key must be 256 bits (32 bytes) for AES-256-GCM.");

        }

        std::vector<uint8_t> plaintext(ciphertext.size());

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

        if(!ctx) {

            throw std::runtime_error("Failed to create EVP_CIPHER_CTX.");

        }

        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), init_vec.data());

        int length = 0;

        EVP_DecryptUpdate(ctx, plaintext.data(), &length, ciphertext.data(), ciphertext.size());

        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<uint8_t*>(auth_tag.data()));

        int final_length = 0;

        EVP_DecryptFinal_ex(ctx, plaintext.data() + length, &final_length);
        EVP_CIPHER_CTX_free(ctx);

        return plaintext;

    }

}