#include "dilithium.hpp"

namespace pqc {

    Dilithium::Dilithium(const std::string variant) {

        sig_ = OQS_SIG_new(variant.c_str());

        if(sig_ == nullptr) {

            throw std::runtime_error("Failed to initialize Dilithium signature scheme with variant: " + variant);

        }

    }

    Dilithium::~Dilithium() {

        OQS_SIG_free(sig_);

    }

    SigKeypair Dilithium::keygen() {

        SigKeypair kp;

        kp.public_key.resize(sig_ -> length_public_key);
        kp.private_key.resize(sig_ -> length_secret_key);

        if(OQS_SIG_keypair(sig_, kp.public_key.data(), kp.private_key.data()) != OQS_SUCCESS) {
            
            throw std::runtime_error("Key generation failed for Dilithium signature scheme.");

        }

        return kp;

    }

    std::vector<uint8_t> Dilithium::sign(const std::vector<uint8_t>& message, const std::vector<uint8_t>& private_key) {

        std::vector<uint8_t> signature(sig_ -> length_signature);

        size_t sig_size = 0;

        if(OQS_SIG_sign(sig_, signature.data(), &sig_size, message.data(), message.size(), private_key.data()) != OQS_SUCCESS) {

            throw std::runtime_error("Signing failed for Dilithium signature scheme.");

        }

        signature.resize(sig_size);

        return signature;

    }

    bool Dilithium::verify(const std::vector<uint8_t>& message, const std::vector<uint8_t>& signature, const std::vector<uint8_t>& public_key) {

        return OQS_SIG_verify(sig_, message.data(), message.size(), signature.data(), signature.size(), public_key.data()) == OQS_SUCCESS;

    }

}