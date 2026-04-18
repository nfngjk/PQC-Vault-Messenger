#include "server.hpp"
#include "core/aes_gcm.hpp"

#include <iostream>
#include <cstring>
#include <stdexcept>

#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

namespace pqc {

    Server::Server(int port): port_(port), server_forward_(-1) {

        WSADATA wsa;

        if(WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {

            throw std::runtime_error("Failed to initialize Winsock");

        }

    }

    Server::~Server() {

        if(server_forward_ != -1) {

            closesocket(server_forward_);

        }

        WSACleanup();

    }

    void Server::send_raw_message(int forward, const std::vector<uint8_t>& data) {

        uint32_t length = htonl(data.size());

        send(forward, reinterpret_cast<const char*>(&length), 4, 0);
        send(forward, reinterpret_cast<const char*>(data.data()), data.size(), 0);

    }

    std::vector<uint8_t> Server::receive_raw_message(int forward) {

        uint32_t length = 0;

        recv(forward, reinterpret_cast<char*>(&length), 4, MSG_WAITALL);

        length = ntohl(length);

        std::vector<uint8_t> buffer(length);

        recv(forward, reinterpret_cast<char*>(buffer.data()), length, MSG_WAITALL);

        return buffer;

    }

    void Server::send_encrypted_message(int forward, const std::vector<uint8_t>& key, const std::string& message) {

        std::vector<uint8_t> plaintext(message.begin(), message.end());

        auto result = AesGcm::encrypt(plaintext, key);

        std::vector<uint8_t> packet;

        packet.insert(packet.end(), result.init_vec.begin(), result.init_vec.end());
        packet.insert(packet.end(), result.auth_tag.begin(), result.auth_tag.end());
        packet.insert(packet.end(), result.ciphertext.begin(), result.ciphertext.end());

        send_raw_message(forward, packet);

    }

    std::string Server::receive_encrypted_message(int forward, const std::vector<uint8_t>& key) {

        auto packet = receive_raw_message(forward);

        if(packet.size() < 28) {

            throw std::runtime_error("Invalid packet received");

        }

        std::vector<uint8_t> init_vec(packet.begin(), packet.begin() + 12);
        std::vector<uint8_t> auth_tag(packet.begin() + 12, packet.begin() + 28);
        std::vector<uint8_t> ciphertext(packet.begin() + 28, packet.end());

        auto plaintext = AesGcm::decrypt(ciphertext, key, init_vec, auth_tag);

        return std::string(plaintext.begin(), plaintext.end());
 
    }
    
    void Server::handle_client(int client_forward) {

        std::cout << "Client connected" << std::endl;

        auto kp = Handshake::server_init();

        send_raw_message(client_forward, kp.public_key);

        std::cout << "Sent public key to client" << std::endl;

        auto ciphertext = receive_raw_message(client_forward);
        auto session = Handshake::server_handshake(ciphertext, kp.private_key);

        std::cout << "Handshake completed, channel established" << std::endl;

        while(true) {

            try {

                auto message = receive_encrypted_message(client_forward, session.shared_private_key);

                std::cout << "[Client] " << message << std::endl;

                if(message == "/quit") {

                    std::cout << "Client disconnected" << std::endl;

                    break;

                }

            }

            catch(...) {

                std::cout << "Error receiving message, closing connection" << std::endl;

                break;
                
            }

            std::cout << "[You] ";

            std::string reply;

            std::getline(std::cin, reply);

            send_encrypted_message(client_forward, session.shared_private_key, reply);

        }

        closesocket(client_forward);

    }

    void Server::run() {

        std::cout << "Starting server on port " << port_ << "...\n";
        std::cout.flush();

        server_forward_ = socket(AF_INET, SOCK_STREAM, 0);

        if(server_forward_ == INVALID_SOCKET) {

            throw std::runtime_error("Failed to create socket...");

        }

        sockaddr_in address{};

        address.sin_family = AF_INET;
        address.sin_port = htons(port_);
        address.sin_addr.s_addr = INADDR_ANY;

        if(bind(server_forward_, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == SOCKET_ERROR) {

            throw std::runtime_error("Bind failed...");

        }

        listen(server_forward_, 1);

        std::cout << "Listen on port: " << port_ << std::endl;

        sockaddr_in client_address{};

        int address_length = sizeof(client_address);
        int client_forward = accept(server_forward_, reinterpret_cast<sockaddr*>(&client_address), &address_length);

        if(client_forward == INVALID_SOCKET) {

            throw std::runtime_error("Accept failed...");

        }

        handle_client(client_forward);

    }

}