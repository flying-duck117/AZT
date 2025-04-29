#ifndef ADHOC_UDP_INTERFACE_HPP
#define ADHOC_UDP_INTERFACE_HPP

#include <string>
#include <stdexcept>
#include <cstring>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <netinet/in.h>

class UDPInterface {
public:
    UDPInterface(int port, const char* interface = "wlan0") : my_port(port) {
        if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
            throw std::runtime_error("Socket creation failed");
        }

        // Enable address/port reuse
        int reuse = 1;
        if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
            close(sock);
            throw std::runtime_error("Failed to set reuse option");
        }

        // Enable broadcast
        int broadcast = 1;
        if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast)) < 0) {
            close(sock);
            throw std::runtime_error("Failed to set broadcast option");
        }

        // Get our own IP address
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

        // Get interface IP address
        if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
            close(sock);
            throw std::runtime_error("Failed to get interface address");
        }
        my_addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;

        // Bind to interface
        if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0) {
            close(sock);
            throw std::runtime_error("Failed to bind to interface");
        }

        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = INADDR_ANY;

        if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            close(sock);
            throw std::runtime_error("Bind failed");
        }
    }

    ~UDPInterface() { 
        close(sock); 
    }

    void broadcast(const std::string& msg) {
        addr.sin_addr.s_addr = INADDR_BROADCAST;
        if (sendto(sock, msg.c_str(), msg.size(), 0, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            throw std::runtime_error("Broadcast failed");
        }
    }

    std::string receiveFrom(struct sockaddr_in& client_addr) {
        char buffer[1024];
        socklen_t addr_len = sizeof(client_addr);
        
        while (true) {
            int n = recvfrom(sock, buffer, sizeof(buffer)-1, 0, 
                           (struct sockaddr*)&client_addr, &addr_len);
            
            if (n < 0) {
                throw std::runtime_error("Receive failed");
            }
            
            // Skip message if it's from ourselves
            if (client_addr.sin_addr.s_addr == my_addr && 
                ntohs(client_addr.sin_port) == my_port) {
                continue;
            }
            
            buffer[n] = '\0';
            return std::string(buffer);
        }
    }

    void sendTo(const std::string& dest_addr, const std::string& msg, int port) {
        struct sockaddr_in dest{};
        dest.sin_family = AF_INET;
        dest.sin_port = htons(port);
        if (inet_pton(AF_INET, dest_addr.c_str(), &dest.sin_addr) <= 0) {
            throw std::runtime_error("Invalid address");
        }

        if (sendto(sock, msg.c_str(), msg.size(), 0, 
                  (struct sockaddr*)&dest, sizeof(dest)) < 0) {
            throw std::runtime_error("SendTo failed");
        }
    }

private:
    int sock;
    struct sockaddr_in addr;
    in_addr_t my_addr;
    int my_port;
};

#endif