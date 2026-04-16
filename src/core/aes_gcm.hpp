#pragma once

#include <vector>
#include <string>
#include <stdexcept>
#include <cstdint>

namespace pqc {

    struct AesGcmKeys {

        std::vector<uint8_t> ciphertext;
        std::vector<uint8_t> init_vec;
        std::vector<uint8_t> auth_tag;

    };

    class AesGcm {

        public:

            static AesGcmKeys encrypt(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& key);
            static std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& key, const std::vector<uint8_t>& init_vec, const std::vector<uint8_t>& auth_tag);
       
    };

}

