#ifndef KUBE_UDP_INTERFACE_HPP
#define KUBE_UDP_INTERFACE_HPP

#include <string>
#include <cstring>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <stdexcept>
#include <unordered_map>
#include <iostream>

class UDPInterface {
public:
    UDPInterface(int port) {
        try {
            if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
                std::cerr << "UDP socket creation failed: " << strerror(errno) << std::endl;
                return;
            }

            int reuse = 1;
            int bufSize = 262144;
            if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0 ||
                setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &bufSize, sizeof(bufSize)) < 0) {
                std::cerr << "Socket option failed: " << strerror(errno) << std::endl;
            }

            memset(&server_addr, 0, sizeof(server_addr));
            server_addr.sin_family = AF_INET;
            server_addr.sin_port = htons(port);
            server_addr.sin_addr.s_addr = INADDR_ANY;

            if (bind(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
                std::cerr << "UDP bind failed: " << strerror(errno) << std::endl;
                close(sock);
            }
        } catch (const std::exception& e) {
            std::cerr << "Init error: " << e.what() << std::endl;
        }
    }

    ~UDPInterface() { if (sock >= 0) close(sock); }

    void broadcast(const std::string& msg) {
        try {
            if (cached_addrs.empty()) {
                for (int i = 1; i <= droneCount; ++i) {
                    cacheAddress("drone" + std::to_string(i) + "-service.default", 65457);
                }
            }

            for (const auto& [key, addr] : cached_addrs) {
                if (sendto(sock, msg.c_str(), msg.size(), 0, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
                    std::cerr << "Send failed to " << key << ": " << strerror(errno) << std::endl;
                }
            }
        } catch (const std::exception& e) {
            std::cerr << "Broadcast error: " << e.what() << std::endl;
        }
    }

    void sendTo(const std::string& containerName, const std::string& msg, int port) {
        try {
            string key = containerName + ":" + std::to_string(port);
            if (cached_addrs.find(key) == cached_addrs.end()) {
                cacheAddress(containerName, port);
            }

            if (sendto(sock, msg.c_str(), msg.size(), 0, 
                      (struct sockaddr*)&cached_addrs[key], sizeof(sockaddr_in)) < 0) {
                std::cerr << "SendTo failed for " << containerName << ": " << strerror(errno) << std::endl;
            }
        } catch (const std::exception& e) {
            std::cerr << "SendTo error: " << e.what() << std::endl;
        }
    }

    std::string receiveFrom(sockaddr_in& client_addr) {
        try {
            char buffer[4096];
            socklen_t addr_len = sizeof(client_addr);
            int n = recvfrom(sock, buffer, sizeof(buffer) - 1, 0, 
                           (struct sockaddr*)&client_addr, &addr_len);
            
            if (n < 0) {
                std::cerr << "Receive failed: " << strerror(errno) << std::endl;
                return "";
            }
            buffer[n] = '\0';
            return buffer;
        } catch (const std::exception& e) {
            std::cerr << "Receive error: " << e.what() << std::endl;
            return "";
        }
    }

private:
    int sock = -1;
    struct sockaddr_in server_addr;
    std::unordered_map<string, struct sockaddr_in> cached_addrs;
    const int droneCount = std::stoi(std::getenv("DRONE_COUNT"));

    void cacheAddress(const std::string& containerName, int port) {
        struct addrinfo hints = {}, *result;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;

        string key = containerName + ":" + std::to_string(port);
        int status = getaddrinfo(containerName.c_str(), std::to_string(port).c_str(), &hints, &result);
        
        if (status == 0) {
            cached_addrs[key] = *(struct sockaddr_in*)result->ai_addr;
            freeaddrinfo(result);
        } else {
            std::cerr << "DNS resolution failed for " << containerName << ": " << gai_strerror(status) << std::endl;
        }
    }
};

#endif