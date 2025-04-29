#include <cstring>
#include <stdexcept>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <iostream>
#include <thread>
#include <atomic>
#include <functional>

class IPCServer {
private:
    int server_fd;
    int client_fd = -1;
    int port;
    struct sockaddr_in address;
    const int BUFFER_SIZE = 1024;
    std::thread server_thread;
    std::atomic<bool> running{false};
    std::function<void(const std::string&)> data_callback;

    void handleClient() {
        char buffer[BUFFER_SIZE];
        
        while (running && client_fd != -1) {
            int bytes_read = read(client_fd, buffer, BUFFER_SIZE - 1);
            if (bytes_read > 0) {
                buffer[bytes_read] = '\0';
                std::string received_data(buffer, bytes_read);
                
                if (data_callback) {
                    data_callback(received_data);
                }
                
                // Send acknowledgment
                const char* response = "ok";
                send(client_fd, response, strlen(response), 0);
            } else if (bytes_read == 0) {
                // Client disconnected
                std::cout << "Client disconnected" << std::endl;
                close(client_fd);
                client_fd = -1;
                break;
            } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
                // Error occurred
                std::cerr << "Read error: " << strerror(errno) << std::endl;
                close(client_fd);
                client_fd = -1;
                break;
            }
        }
    }

    void serverLoop() {
        int addrlen = sizeof(address);
        
        while (running) {
            if (client_fd == -1) {
                // Wait for new client connection
                client_fd = accept(server_fd, (struct sockaddr *)&address, 
                                 (socklen_t*)&addrlen);
                
                if (client_fd >= 0) {
                    std::cout << "Client connected" << std::endl;
                    handleClient();
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        if (client_fd != -1) {
            close(client_fd);
            client_fd = -1;
        }
    }

public:
    IPCServer(int port, std::function<void(const std::string&)> callback = nullptr) 
        : port(port), server_fd(-1), data_callback(callback) {
        
        if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
            throw std::runtime_error("Socket creation failed");
        }

        int opt = 1;
        if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
            throw std::runtime_error("setsockopt failed");
        }

        address.sin_family = AF_INET;
        address.sin_addr.s_addr = INADDR_ANY;
        address.sin_port = htons(port);

        if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
            throw std::runtime_error("Bind failed");
        }

        if (listen(server_fd, 1) < 0) {  // Listen for single connection
            throw std::runtime_error("Listen failed");
        }

        std::cout << "Server listening on port " << port << std::endl;
    }

    void setCallback(std::function<void(const std::string&)> callback) {
        data_callback = callback;
    }

    void start() {
        if (!running) {
            running = true;
            server_thread = std::thread(&IPCServer::serverLoop, this);
        }
    }

    void stop() {
        if (running) {
            running = false;
            if (server_thread.joinable()) {
                server_thread.join();
            }
        }
    }

    ~IPCServer() {
        stop();
        if (client_fd != -1) {
            close(client_fd);
        }
        if (server_fd != -1) {
            close(server_fd);
        }
    }
};