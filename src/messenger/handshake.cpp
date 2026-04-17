#include "handshake.hpp"

namespace pqc {

    Keypair Handshake::server_init() {

        Kyber kyber;

        return kyber.keygen();

    }

    std::pair<std::vector<uint8_t>, Session> Handshake::client_handshake(const std::vector<uint8_t>& server_public_key) {

        Kyber kyber;

        auto encaps_result = kyber.encapsulate(server_public_key);

        Session session;

        session.shared_private_key = std::vector<uint8_t>(encaps_result.shared_private.begin(), encaps_result.shared_private.begin() + 32);

        return {encaps_result.ciphertext, session};

    }

    Session Handshake::server_handshake(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& server_private_key) {

        Kyber kyber;

        auto shared_private = kyber.decapsulate(ciphertext, server_private_key);

        Session session;

        session.shared_private_key = std::vector<uint8_t>(shared_private.begin(), shared_private.begin() + 32);

        return session;

    }

}