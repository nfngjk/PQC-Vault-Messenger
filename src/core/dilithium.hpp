#pragma once

#include <vector>
#include <string>
#include <stdexcept>

extern "C" {
    
    #include <oqs/oqs.h>

}

namespace pqc {

    struct SigKeypair {
      
        std::vector<uint8_t> public_key;
        std::vector<uint8_t> private_key;
    
    };

    class Dilithium {

        public:

            Dilithium(const std::string variant = "ML-DSA-65");

            ~Dilithium();

            SigKeypair keygen();

            std::vector<uint8_t> sign(const std::vector<uint8_t>& message, const std::vector<uint8_t>& private_key);

            bool verify(const std::vector<uint8_t>& message, const std::vector<uint8_t>& signature, const std::vector<uint8_t>& public_key);

        private:

            OQS_SIG* sig_;

    };

}