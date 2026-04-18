#include "client.hpp"
#include "core/aes_gcm.hpp"

#include <iostream>
#include <stdexcept>

#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

namespace pqc {

    Client::Client(const std::string& host, int port): host_(host), port_(port), socket_forward_(-1) {

        WSADATA wsa;

        if(WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {

            throw std::runtime_error("WSAStartup failed...");

        }

    }

    Client::~Client() {

        if(socket_forward_ != -1) {

            closesocket(socket_forward_);

        }

        WSACleanup();

    }

    void Client::send_raw_message(int forward, const std::vector<uint8_t>& data) {

        uint32_t length = htonl(data.size());

        send(forward, reinterpret_cast<const char*>(&length), 4, 0);
        send(forward, reinterpret_cast<const char*>(data.data()), data.size(), 0);

    }

    std::vector<uint8_t> Client::receive_raw_message(int forward) {

        uint32_t length = 0;

        recv(forward, reinterpret_cast<char*>(&length), 4, MSG_WAITALL);

        length = ntohl(length);

        std::vector<uint8_t> buffer(length);

        recv(forward, reinterpret_cast<char*>(buffer.data()), length, MSG_WAITALL);

        return buffer;

    }

    void Client::send_encrypt_message(int forward, const std::vector<uint8_t>& key, const std::string& message) {

        std::vector<uint8_t> plaintext(message.begin(), message.end());

        auto result = AesGcm::encrypt(plaintext, key);

        std::vector<uint8_t> packet;

        packet.insert(packet.end(), result.init_vec.begin(), result.init_vec.end());
        packet.insert(packet.end(), result.auth_tag.begin(), result.auth_tag.end());
        packet.insert(packet.end(), result.ciphertext.begin(), result.ciphertext.end());

        send_raw_message(forward, packet);

    }

    std::string Client::receive_encrypted_message(int forward, const std::vector<uint8_t>& key) {

        auto packet = receive_raw_message(forward);

        if(packet.size() < 28) {

            throw std::runtime_error("Packet too short...");

        }

        std::vector<uint8_t> init_vec(packet.begin(), packet.begin() + 12);
        std::vector<uint8_t> auth_tag(packet.begin() + 12, packet.begin() + 28);
        std::vector<uint8_t> ciphertext(packet.begin() + 28, packet.end());

        auto plaintext = AesGcm::decrypt(ciphertext, key, init_vec, auth_tag);

        return std::string(plaintext.begin(), plaintext.end());

    }

    void Client::run() {

        socket_forward_ = socket(AF_INET, SOCK_STREAM, 0);

        if(socket_forward_ == INVALID_SOCKET) {

            throw std::runtime_error("Failed to create socket...");

        }

        sockaddr_in address{};

        address.sin_family = AF_INET;
        address.sin_port = htons(port_);
        
        inet_pton(AF_INET, host_.c_str(), &address.sin_addr);

        if(connect(socket_forward_, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == SOCKET_ERROR) {

            throw std::runtime_error("Failed to connect to " + host_ + ": " + std::to_string(port_) + "...");

        }

        std::cout << "Connect to " << host_ << ": " << port_ << std::endl;

        auto server_public_key = receive_raw_message(socket_forward_);

        std::cout << "Receive server public key..." << std::endl;

        auto [ciphertext, session] = Handshake::client_handshake(server_public_key);

        send_raw_message(socket_forward_, ciphertext);

        std::cout << "Handshake complete, channel established" << std::endl;

        while(true) {

            std::cout << "[You] ";

            std::string message;

            getline(std::cin, message);

            send_encrypt_message(socket_forward_, session.shared_private_key, message);

            if(message == "/quit") {

                break;

            }

            try {

                auto reply = receive_encrypted_message(socket_forward_, session.shared_private_key);

                std::cout << "[Server] " << reply << std::endl;

            }

            catch(...) {

                std::cout << "Connection closed..." << std::endl;

                break;

            }

        }

    }

}