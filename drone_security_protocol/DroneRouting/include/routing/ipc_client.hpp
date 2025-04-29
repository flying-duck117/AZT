#include <cstring>
#include <stdexcept>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <iostream>
#include <chrono>
#include <thread>

class ipc_client {
private:
    int sock;
    int port;
    struct sockaddr_in serv_addr;
    bool connected = false;

    void connect_to_server() {
        if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            throw std::runtime_error("Socket creation error");
        }
  
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(port);
    
        if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
            throw std::runtime_error("Invalid address/Address not supported");
        }
  
        if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
            throw std::runtime_error("Connection failed");
        }

        connected = true;
        std::cout << "Connected to server on port " << port << std::endl;
    }

public:
    ipc_client(int port) : port(port) {
        connect_to_server();
    }

    void sendData(const std::string& data) {
        if (!connected) {
            try {
                connect_to_server();
            } catch (const std::exception& e) {
                throw std::runtime_error("Failed to reconnect: " + std::string(e.what()));
            }
        }

        if (send(sock, data.c_str(), data.length(), 0) < 0) {
            connected = false;
            throw std::runtime_error("Failed to send data");
        }

        char buffer[1024] = {0};
        int bytes_read = read(sock, buffer, sizeof(buffer)-1);
        if (bytes_read <= 0) {
            connected = false;
            throw std::runtime_error("Failed to receive acknowledgment");
        }
    }

    ~ipc_client() {
        if (sock != -1) {
            close(sock);
        }
    }
};