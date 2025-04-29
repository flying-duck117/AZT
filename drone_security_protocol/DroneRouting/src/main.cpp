#include <memory>
#include <routing/drone.hpp>
#include "ipc_client.hpp"

void runTerminal() {
    try {
        ipc_client client(60137);
        std::cout << "\n=== Interactive Terminal ===\n"
                  << "Available commands:\n"
                  << "  discover <addr>                         - Initiate route discovery\n"
                  << "  auto-discover <addr> <secs> <count>    - Automatically discover routes every N seconds\n"
                  << "                                           for count times (0 = infinite)\n"
                  << "  verify                                 - Verify current routes\n"
                  << "  leave                                  - Leave the swarm\n"
                  << "  (Ctrl+D to exit)\n\n";

        std::unique_ptr<std::thread> autoDiscoverThread;
        std::atomic<bool> running{false};

        std::string input;
        while (std::getline(std::cin, input)) {
            try {
                std::istringstream iss(input);
                std::string command;
                iss >> command;

                if (command == "discover") {
                    std::string destAddr;
                    if (!(iss >> destAddr)) {
                        std::cout << "Usage: discover <destination_address>\n";
                        continue;
                    }
                    client.sendData(json{
                        {"type", INIT_ROUTE_DISCOVERY}, 
                        {"destAddr", destAddr},
                        {"from_ipc", true},
                        {"srcAddr", "ipc_client"}
                    }.dump());
                }
                else if (command == "auto-discover") {
                    // Stop any existing auto-discover thread
                    if (autoDiscoverThread) {
                        running = false;
                        autoDiscoverThread->join();
                        autoDiscoverThread.reset();
                        std::cout << "Stopped previous auto-discover.\n";
                    }

                    std::string destAddr;
                    int interval, count;
                    if (!(iss >> destAddr >> interval >> count) || interval < 1 || count < 0) {
                        std::cout << "Usage: auto-discover <addr> <interval_seconds> <count>\n"
                                 << "       interval >= 1, count >= 0 (0 = infinite)\n";
                        continue;
                    }

                    running = true;
                    autoDiscoverThread = std::make_unique<std::thread>(
                        [&client, &running, destAddr, interval, count]() {
                            int sent = 0;
                            while (running && (count == 0 || sent < count)) {
                                client.sendData(json{
                                    {"type", INIT_ROUTE_DISCOVERY},
                                    {"destAddr", destAddr},
                                    {"from_ipc", true},
                                    {"srcAddr", "ipc_client"}
                                }.dump());

                                std::cout << "Auto-discover: Sent request " << ++sent
                                         << (count ? "/" + std::to_string(count) : "")
                                         << " to " << destAddr << std::endl;

                                if (sent == count) break;
                                std::this_thread::sleep_for(std::chrono::seconds(interval));
                            }
                        }
                    );

                    std::cout << "Started auto-discover to " << destAddr
                             << " every " << interval << " seconds"
                             << (count ? " for " + std::to_string(count) + " times" : " indefinitely")
                             << std::endl;
                }
                else if (command == "verify") {
                    client.sendData(json{
                        {"type", VERIFY_ROUTE},
                        {"from_ipc", true},
                        {"srcAddr", "ipc_client"}
                    }.dump());
                }
                else if (command == "leave") {
                    client.sendData(json{
                        {"type", INIT_LEAVE},
                        {"from_ipc", true},
                        {"srcAddr", "ipc_client"}
                    }.dump());
                }
                else {
                    std::cout << "Unknown command. Use discover, auto-discover, verify, or leave\n";
                }
            } catch (const std::exception& e) {
                std::cerr << "Error: " << e.what() << std::endl;
            }
        }
        if (autoDiscoverThread) {
            running = false;
            autoDiscoverThread->join();
        }

    } catch (const std::exception& e) {
        std::cerr << "Terminal Error: " << e.what() << std::endl;
        exit(1);
    }
}

int main(int argc, char* argv[]) {
    if (argc > 1 && std::string(argv[1]) == "--terminal") {
        runTerminal();
        return 0;
    }

    try {
        auto d = std::make_unique<drone>(
            std::stoi(std::getenv("PORT")), 
            std::stoi(std::getenv("NODE_ID"))
        );
        d->start();
        // d->getSignal().wait();
        return 0;
    } catch (const std::exception& e) {
        createLogger("startup")->critical(e.what());
        return 1;
    }
}