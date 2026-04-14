#pragma once

#include <string>
#include <vector>
#include <stdexcept>

extern "C" {

    #include <oqs/oqs.h>

}

namespace pqc {

    struct Keypair {

        std::vector<uint8_t> public_key;
        std::vector<uint8_t> private_key;

    };

    struct Encaps_result {

        std::vector<uint8_t> ciphertext;
        std::vector<uint8_t> shared_private;

    };

    class Kyber {

        public:

            explicit Kyber(const std::string& variant = "Kyber768");

            ~Kyber();

            Keypair keygen();

            Encaps_result encapsulate(const std::vector<uint8_t>& public_key);

            std::vector<uint8_t> decapsulate(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& private_key);

        private:

            OQS_KEM* kem_;

    };

}