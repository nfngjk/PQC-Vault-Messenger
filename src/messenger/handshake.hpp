#pragma once

#include <vector>
#include <string>
#include "core/kyber.hpp"
#include "core/aes_gcm.hpp"

namespace pqc {

    struct Session {

        std::vector<uint8_t> shared_private_key;

    };

    class Handshake {

        public:

            static Keypair server_init();

            static std::pair<std::vector<uint8_t>, Session> client_handshake(const std::vector<uint8_t>& server_public_key);
            
            static Session server_handshake(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& server_private_key);

    };

}