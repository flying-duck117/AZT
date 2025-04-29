#ifndef TCP_SOCKET_HPP
#define TCP_SOCKET_HPP

#include <string>
#include <cstring>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <stdexcept>
#include <vector>
#include <fcntl.h>
#include <iostream>

class TCPInterface {
public:
    TCPInterface(int port, bool is_server = true) : is_server(is_server) {
        if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            throw std::runtime_error("TCP socket creation failed");
        }

        if (is_server) {
            memset(&server_addr, 0, sizeof(server_addr));
            server_addr.sin_family = AF_INET;
            server_addr.sin_addr.s_addr = INADDR_ANY;
            server_addr.sin_port = htons(port);

            if (bind(sock, (const struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
                close(sock);
                throw std::runtime_error("TCP bind failed");
            }

            if (listen(sock, 5) < 0) {
                close(sock);
                throw std::runtime_error("TCP listen failed");
            }
        }
    }

    ~TCPInterface() {
        close(sock);
    }

    int accept_connection() {
        if (!is_server) {
            return -1;
        }

        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int client_sock = accept(sock, (struct sockaddr *)&client_addr, &addr_len);

        if (client_sock < 0) {
            return -1;
        }

        print_peer_address(client_sock);

        return client_sock;
    }

    int connect_to(const std::string& host, int port, int timeout_sec = 10) {
        if (is_server) {
            return -1;
        }

        struct addrinfo hints, *result;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;

        int status = getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &result);
        if (status != 0) {
            return -1;
        }

        int flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);

        int res = connect(sock, result->ai_addr, result->ai_addrlen);
        if (res < 0) {
            if (errno == EINPROGRESS) {
                struct timeval tv;
                tv.tv_sec = timeout_sec;
                tv.tv_usec = 0;

                fd_set fdset;
                FD_ZERO(&fdset);
                FD_SET(sock, &fdset);

                res = select(sock + 1, NULL, &fdset, NULL, &tv);
                if (res == 0) {
                    freeaddrinfo(result);
                    return -2;
                } else if (res < 0) {
                    freeaddrinfo(result);
                    return -1;
                } else {
                    int error;
                    socklen_t len = sizeof(error);
                    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &len) < 0 || error != 0) {
                        freeaddrinfo(result);
                        return -1;
                    }
                }
            } else {
                freeaddrinfo(result);
                return -1;
            }
        }

        fcntl(sock, F_SETFL, flags);

        freeaddrinfo(result);
        return 0;
    }

    int send_data(const std::string& msg, int client_sock = -1, int timeout_sec = 5) {
        int target_sock = (client_sock == -1) ? sock : client_sock;

        struct timeval tv;
        tv.tv_sec = timeout_sec;
        tv.tv_usec = 0;
        if (setsockopt(target_sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof tv) < 0) {
            return -1;
        }

        ssize_t bytes_sent = send(target_sock, msg.c_str(), msg.size(), 0);
        if (bytes_sent < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                return -1;
            } else {
                return -1;
            }
        }

        return bytes_sent;
    }

    std::string receive_data(int client_sock = -1, size_t buffer_size = 1024) {
        int target_sock = (client_sock == -1) ? sock : client_sock;
        std::vector<char> buffer(buffer_size);
        ssize_t bytes_received = recv(target_sock, buffer.data(), buffer.size(), 0);

        if (bytes_received < 0) {
            throw std::runtime_error("Error receiving data: " + std::string(strerror(errno)));
        } else if (bytes_received == 0) {
            throw std::runtime_error("Connection closed by peer");
        }

        print_peer_address(target_sock);

        return std::string(buffer.data(), bytes_received);
    }

    int set_non_blocking(bool non_blocking) {
        int flags = fcntl(sock, F_GETFL, 0);
        if (flags == -1) {
            return -1;
        }

        if (non_blocking) {
            flags |= O_NONBLOCK;
        } else {
            flags &= ~O_NONBLOCK;
        }

        if (fcntl(sock, F_SETFL, flags) == -1) {
            return -1;
        }

        return 0;
    }

private:
    int sock;
    struct sockaddr_in server_addr;
    bool is_server;

    void print_peer_address(int client_sock) {
        struct sockaddr_in addr;
        socklen_t addr_len = sizeof(addr);

        if (getpeername(client_sock, (struct sockaddr*)&addr, &addr_len) == -1) {
            std::cerr << "Error getting peer name: " << strerror(errno) << std::endl;
            return;
        }

        char ip[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, &(addr.sin_addr), ip, INET_ADDRSTRLEN) == nullptr) {
            std::cerr << "Error converting IP to string: " << strerror(errno) << std::endl;
            return;
        }
    }
};

#endif