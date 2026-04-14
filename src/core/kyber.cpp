#include "kyber.hpp"

namespace pqc {

    Kyber::Kyber(const std::string& variant) {

        kem_ = OQS_KEM_new(variant.c_str());

        if(kem_ == nullptr) {
            
            throw std::runtime_error("Failed to initialize Kyber KEM with variant: " + variant);
        
        }

    }

    Kyber::~Kyber() {

        OQS_KEM_free(kem_);

    }

    Keypair Kyber::keygen() {

        Keypair kp;

        kp.public_key.resize(kem_ -> length_public_key);
        kp.private_key.resize(kem_ -> length_secret_key);

        if(OQS_KEM_keypair(kem_, kp.public_key.data(), kp.private_key.data()) != OQS_SUCCESS) {
            
            throw std::runtime_error("Key generation failed for Kyber KEM.");

        }

        return kp;

    }

    Encaps_result Kyber::encapsulate(const std::vector<uint8_t>& public_key) {

        Encaps_result result;

        result.ciphertext.resize(kem_ -> length_ciphertext);
        result.shared_private.resize(kem_ -> length_shared_secret);

        if(OQS_KEM_encaps(kem_, result.ciphertext.data(), result.shared_private.data(), public_key.data()) != OQS_SUCCESS) {
            
            throw std::runtime_error("Encapsulation failed for Kyber KEM.");

        }

        return result;

    }

    std::vector<uint8_t> Kyber::decapsulate(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& private_key) {

        std::vector<uint8_t> shared_private(kem_ -> length_shared_secret);

        if(OQS_KEM_decaps(kem_, shared_private.data(), ciphertext.data(), private_key.data()) != OQS_SUCCESS) {
            
            throw std::runtime_error("Decapsulation failed for Kyber KEM.");

        }

        return shared_private;

    }

}

