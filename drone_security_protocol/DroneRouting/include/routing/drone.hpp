#ifndef DRONE_HPP
#define DRONE_HPP
#define BRDCST_PORT 65457
#include <cstring>
#include <mutex>
#include <cstdlib>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <tuple>
#include <thread>
#include <set>
#include <deque>
#include <queue>
#include <unordered_map>
#include <unordered_set>
#include <stdexcept>
#include <sstream>
#include <vector>
#include <random>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <netdb.h>
#include <nlohmann/json.hpp>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <chrono>
#include <sys/time.h>
#include <ctime>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/fmt/chrono.h>
#include <atomic>
#include <condition_variable>
#include <future>
#include <set>
#include "httplib.h"
#include "hashTree.hpp"
#include "messages.hpp"
#include <spdlog/fmt/chrono.h>
#include "ipc_server.hpp"
#include "routingMap.hpp"
#include "routingTableEntry.hpp"
#include "pki_client.hpp"
#include "network_adapters/ad_hoc_udp_interface.hpp" // change to ad hoc if needed
#include "network_adapters/tcp_interface.hpp"

using json = nlohmann::json;
using std::cout;
using std::endl;
using std::string;

inline spdlog::level::level_enum getLogLevelFromEnv() {
    const char* levelEnv = std::getenv("LOG_LEVEL");
    std::string levelStr = levelEnv ? levelEnv : "";
    
    if (levelStr.empty()) {
        return spdlog::level::info;
    }
    
    static const std::unordered_map<std::string, spdlog::level::level_enum> levelMap = {
        {"TRACE", spdlog::level::trace},
        {"DEBUG", spdlog::level::debug},
        {"INFO", spdlog::level::info},
        {"WARN", spdlog::level::warn},
        {"ERROR", spdlog::level::err},
        {"CRITICAL", spdlog::level::critical},
        {"off", spdlog::level::off}
    };

    auto it = levelMap.find(levelStr);
    if (it == levelMap.end()) {
        return spdlog::level::info;
    }
    return it->second;
}

inline std::shared_ptr<spdlog::logger> createLogger(const std::string& name) {
    static bool initialized = false;
    auto level = getLogLevelFromEnv();
    
    if (!initialized) {
        spdlog::set_level(level);
        initialized = true;
    }

    auto logger = std::make_shared<spdlog::logger>(
        name,
        std::make_shared<spdlog::sinks::stdout_color_sink_mt>()
    );
    logger->set_pattern("[%^%l%$] [%n] %v");
    
    // Explicitly set the logger's level
    logger->set_level(level);
    return logger;
}

class drone {
    public:
        drone(int port, int nodeID);
        void start();
        int send(const string&, string, bool=false);
        void broadcast(const string& msg);
        std::future<void> getSignal();
        // Sends the current valid node list to all swarm members
        void propagateValidNodeList();
        // Cross-swarm communication methods
        void initCrossSwarmRouteDiscovery(const string& destAddr);
        void handleCrossSwarmRREQ(json& data);
        void handleCrossSwarmRREP(json& data);
        void broadcastToOtherLeaders(const string& serializedMsg, const string& originLeader);
        std::vector<string> getOtherLeaderAddresses();

    private:
        class TESLA {
            public:
                TESLA();
                ~TESLA();
                struct nonce_data {
                    std::string nonce;
                    std::string tesla_key;
                    std::string auth;
                    std::string destination;
                };

                RoutingMap<string, ROUTING_TABLE_ENTRY> routingTable;
                const std::chrono::seconds disclosure_interval = std::chrono::seconds(std::stoul(std::getenv("TESLA_DISCLOSE")));
                INIT_MESSAGE init_tesla(const string&);
                string getCurrentHash();

                void insert(const std::string& key, nonce_data value) {
                    if (this->nonce_map.find(key) != this->nonce_map.end()) {
                        logger->debug("Key '{}' already exists. Updating value.", key);
                    }
                    
                    this->nonce_map[key] = value;
                }

                nonce_data getNonceData(const std::string& key) {

                    if (nonce_map.find(key) != nonce_map.end()) {
                        return nonce_map[key];
                    } else {
                        throw std::runtime_error("Key: " + key + " not found in nonce map");
                    }
                }

                void printNonceMap() {
                    for (const auto& entry : nonce_map) {
                        logger->debug("Entry:");
                        logger->debug("  Key: {}", entry.first);
                        logger->debug("  Nonce: {}", entry.second.nonce);
                        logger->debug("  TESLA Key: {}", entry.second.tesla_key);
                        logger->debug("  Auth: {}", entry.second.auth);
                        logger->debug("  Destination: {}", entry.second.destination);
                    }
                }

            private:
                std::shared_ptr<spdlog::logger> logger;
                struct TimedHash {
                    std::chrono::system_clock::time_point disclosure_time;
                    std::string hash;
                };

                std::unordered_map<string, nonce_data> nonce_map; // If multiple nonce_datas are required, replace with vector

                string addr;
                const unsigned int key_lifetime = 10800; // Hardcoded: 10800 seconds
                const unsigned int numKeys = key_lifetime / disclosure_interval.count();
                // unsigned char (*hashChain)[SHA256_DIGEST_LENGTH];

                std::string sha256(const std::string&);
                std::string createHMAC(const std::string& key, const std::string& data);
                void generateHashChain();
                void compareHashes(const unsigned char *hash1, const unsigned char *hash2);

                /* We can associate each nonce/auth with the specific disclosure time, starting with the beginning of the array at time 0, time n, time 2n, etc. where n is the disclosure time */
                std::vector<string> nonce_list;
                std::deque<TimedHash> timed_hash_chain;
        };
        TESLA tesla;
        struct NetworkNode {
            std::string drone_id;
            std::string certificate;
            std::string manufacturer_id;
            std::string issued_at;
            std::string valid_until;
        };
        std::unordered_map<std::string, NetworkNode> networkNodes;
        std::mutex networkNodesMutex;
        bool requestNetworkNodes();
        void requestNetworkNodesIfLeader();

        std::vector<NetworkNode> getNetworkNodes();
        bool isNodeInNetwork(const std::string& droneId);
        
        // CRL cache to avoid repeated network requests
        std::unordered_map<std::string, bool> crlCache;
        std::chrono::steady_clock::time_point crlCacheLastRefreshed;
        std::mutex crlCacheMutex;
        const std::chrono::minutes crlCacheLifetime{10}; // Cache CRL results for 10 minutes
        void refreshCRLCache(); // Refresh the CRL cache for all known certificates

        string addr;
        int port;
        unsigned long seqNum;
        int nodeID;
        string GCS_IP;
        std::queue<string> messageQueue;
        std::mutex queueMutex;
        std::condition_variable cv;
        std::atomic<bool> running{true};
        std::vector<std::thread> threads;


        struct PendingRoute {
            std::string destAddr;
            std::string msg;
            std::chrono::steady_clock::time_point expirationTime;
        };

        static constexpr size_t MAX_PENDING_ROUTES = 200;
        static constexpr size_t CLEANUP_THRESHOLD = 150;
        std::deque<PendingRoute> pendingRoutes;
        std::mutex pendingRoutesMutex;
        void cleanupExpiredRoutes();
        bool addPendingRoute(const PendingRoute& route);

        std::deque<string> hashChainCache; 

        int sendData(string containerName, const string& msg);
        string sha256(const string& inn);
        void initMessageHandler(json& data);
        void routeRequestHandler(json& data);
        void routeReplyHandler(json& data);
        void routeErrorHandler(json& data);
        void clientResponseThread();
        void initRouteDiscovery(const string&);
        void verifyRouteHandler(json& data);
        void dataHandler(json& data);
        void neighborDiscoveryFunction();
        void neighborDiscoveryHelper();
        void processPendingRoutes();
        void leaveSwarm();
        void leaveHandler(json& data);
        string getHashFromChain(unsigned long seqNum, unsigned long hopCount);

        const uint8_t max_hop_count = std::stoul((std::getenv("MAX_HOP_COUNT"))); // Maximum number of nodes we can/allow route through
        const uint8_t max_seq_count = std::stoul((std::getenv("MAX_SEQ_COUNT")));
        const uint8_t timeout_sec = std::stoul((std::getenv("TIMEOUT_SEC")));
        const uint8_t DISCOVERY_INTERVAL = std::stoul((std::getenv("DISCOVERY_INTERVAL")));
        const bool trigger_rerr = std::getenv("TRIGGER_RERR") ? (std::string(std::getenv("TRIGGER_RERR")) == "True" || std::string(std::getenv("TRIGGER_RERR")) == "true") : false;

        UDPInterface udpInterface;
        TCPInterface tcpInterface;
        std::unique_ptr<IPCServer> ipc_server;

        std::chrono::steady_clock::time_point helloRecvTimer = std::chrono::steady_clock::now();
        std::atomic<bool> discoveryPhaseActive{true};
        const unsigned int helloRecvTimeout = 5; // Acceptable time to wait for a hello message
        std::mutex helloRecvTimerMutex, routingTableMutex;

        string generate_nonce(const size_t length = 16);

        std::shared_ptr<spdlog::logger> logger;

        std::unique_ptr<PKIClient> pki_client;
        std::set<std::string> validatedNodes;
        std::mutex validationMutex;
        std::promise<void> init_promise;
        bool cert_received = false;
        bool isValidatedSender(const std::string& sender);
        void markSenderAsValidated(const std::string& sender);
        std::vector<uint8_t> generateChallengeData(size_t length = 32);
        void challengeResponseHandler(json& data);

        void handleIPCMessage(const std::string&);
        bool isNodeOnCRL(const std::string& nodeAddr);

        bool isLeader = false;
        std::string current_leader;
        std::mutex leaderMutex;
        void broadcastLeaderStatus();
        bool leaderFunctionalityEnabled;

        std::atomic<bool> swarmPhase{false};
        std::vector<std::string> validNodeList;
        std::mutex validNodeListMutex;
        bool hasJoinedSwarm{false};
        
        // Track confirmed swarm members (not just validated nodes)
        std::set<std::string> swarmMembers;
        std::mutex swarmMembersMutex;
        
        // Cross-swarm communication attributes
        std::vector<std::string> knownLeaders; // List of known leader addresses from env var
        std::mutex knownLeadersMutex; // Mutex for thread-safe access to leader list
        std::unordered_set<std::string> visitedLeaders; // Track visited leaders to prevent loops
        
        void sendJoinRequest();
        void joinRequestHandler(json& data);
        void joinResponseHandler(json& data);
        bool isValidSwarmNode(const std::string& addr);
        void propagateValidNodeListAfterJoin(const std::string& requestAddr);
        void transitionToJoinPhase();
};

#endif