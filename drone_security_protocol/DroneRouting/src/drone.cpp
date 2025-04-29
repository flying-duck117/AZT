#include <routing/drone.hpp>

drone::drone(int port, int nodeID) : udpInterface(BRDCST_PORT), tcpInterface(port) {
    logger = createLogger(fmt::format("drone_{}", nodeID));

    this->addr = std::getenv("NODE_IP") ? std::string(std::getenv("NODE_IP")) : throw std::runtime_error("NODE_IP not set");
    this->port = port;
    this->nodeID = nodeID;
    this->seqNum = 1;
    this->GCS_IP = std::getenv("GCS_IP") ? std::getenv("GCS_IP") : "gcs-service.default";

    crlCacheLastRefreshed = std::chrono::steady_clock::time_point();

    this->leaderFunctionalityEnabled = (std::getenv("ENABLE_LEADERSHIP") == nullptr ||
    std::string(std::getenv("ENABLE_LEADERSHIP")) != "false");

    this->isLeader = (std::getenv("IS_LEADER") != nullptr &&
    std::string(std::getenv("IS_LEADER")) == "true");

    const char* otherLeadersEnv = std::getenv("OTHER_LEADERS");
    if (otherLeadersEnv) {
        std::string leaders(otherLeadersEnv);
        std::istringstream iss(leaders);
        std::string leader;

        while (std::getline(iss, leader, ',')) {
            if (!leader.empty()) {
                this->knownLeaders.push_back(leader);
                logger->info("Added known leader: {}", leader);
            }
        }
    }

    const char* sn = std::getenv("SN");
    const char* eeprom_id = std::getenv("EEPROM_ID");

    if (!sn || !eeprom_id) {
        logger->critical("Missing required environment variables: SN and/or EEPROM_ID");
        throw std::runtime_error("Missing required environment variables: SN and/or EEPROM_ID");
    }

    pki_client = std::make_unique<PKIClient>(
        std::string(sn),
        std::string(eeprom_id),
        [this](bool success) {
            logger->info("Certificate status update: {}", success ? "valid" : "invalid");
        }
    );
}

void drone::clientResponseThread() {
    const size_t MAX_QUEUE_SIZE = 200;
    const int QUEUE_WARNING_THRESHOLD = 150;

    while (running) {
        json jsonData;
        std::string rawMessage;
        {
            std::unique_lock<std::mutex> lock(queueMutex);
            cv.wait(lock, [this] { return !messageQueue.empty() || !running; });

            if (!running && messageQueue.empty()) {
                break;
            }

            if (messageQueue.size() >= QUEUE_WARNING_THRESHOLD) {
                logger->warn("Message queue size ({}) approaching maximum capacity ({})",
                           messageQueue.size(), MAX_QUEUE_SIZE);
            }

            if (messageQueue.size() >= MAX_QUEUE_SIZE) {
                logger->error("Message queue full. Dropping oldest message.");
                messageQueue.pop();
            }

            if (!messageQueue.empty()) {
                rawMessage = std::move(messageQueue.front());
                messageQueue.pop();
            } else {
                continue;
            }
        }

        try {
            jsonData = json::parse(rawMessage);
            if (!jsonData.contains("type")) {
                logger->error("Message missing type field: {}", rawMessage);
                continue;
            }

            if (!jsonData["type"].is_number_integer()) {
                logger->error("Message type is not an integer: {}", rawMessage);
                continue;
            }

            int messageType = jsonData["type"].get<int>();
            bool isFromIPC = jsonData.contains("from_ipc") && jsonData["from_ipc"].get<bool>();

            if (messageType == CERTIFICATE_VALIDATION) {

                if (!jsonData.contains("srcAddr")) {
                    logger->error("Message missing srcAddr field");
                    continue;
                }
                std::string srcAddr = jsonData["srcAddr"].get<std::string>();
                if (srcAddr == this->addr) {
                    logger->debug("Ignoring message from self");
                    continue;
                }
                if (!jsonData.contains("type")) {
                    logger->error("Message missing type field");
                    continue;
                }
                auto challenge_type = jsonData["challenge_type"].get<int>();
                if (challenge_type == CHALLENGE_RESPONSE) {
                    logger->info("Processing challenge response from {}", srcAddr);
                    try {
                        if (pki_client->validatePeer(jsonData)) {
                            markSenderAsValidated(srcAddr);
                            logger->info("Successfully validated sender {}", srcAddr);
                        } else {
                            logger->error("Failed to validate sender {}", srcAddr);
                        }
                    } catch (const std::exception& e) {
                        logger->error("Peer validation error: {}", e.what());
                    }
                } else if (challenge_type == CHALLENGE_REQUEST) {
                    logger->info("Processing challenge request from {}", srcAddr);
                    try {
                        ChallengeRequest request;
                        request.deserialize(jsonData);

                        if (pki_client->needsCertificate()) {
                            logger->warn("Cannot respond to challenge - no valid certificate yet");
                            continue;
                        }

                        auto cert = pki_client->getCertificate();
                        if (cert.pem.empty()) {
                            logger->error("No valid certificate available");
                            continue;
                        }

                        ChallengeResponse response;
                        response.type = CERTIFICATE_VALIDATION;
                        response.challenge_type = CHALLENGE_RESPONSE;
                        response.srcAddr = this->addr;
                        response.nonce = request.nonce;
                        response.timestamp = std::chrono::system_clock::now();
                        response.certificate_pem = cert.pem;
                        response.challenge_data = request.challenge_data;

                        std::vector<uint8_t> data_to_sign = request.challenge_data;
                        if (!pki_client->signMessage(data_to_sign)) {
                            logger->error("Failed to sign challenge data");
                            continue;
                        }
                        response.signature = data_to_sign;

                        std::string serialized = response.serialize();
                        if (sendData(request.srcAddr, serialized) != 0) {
                            logger->error("Failed to send challenge response to {}",
                                request.srcAddr);
                        }
                    } catch (const std::exception& e) {
                        logger->error("Error processing challenge request: {}", e.what());
                    }
                }
            continue;
            }

            if (isFromIPC && (messageType == INIT_ROUTE_DISCOVERY || messageType == VERIFY_ROUTE || messageType == INIT_LEAVE)) {
                if (messageType == INIT_ROUTE_DISCOVERY) {
                    // Check if this is a cross-swarm discovery request
                    bool isCrossSwarm = jsonData.contains("isCrossSwarm") && jsonData["isCrossSwarm"].get<bool>();

                    if (isCrossSwarm) {
                        logger->info("Processing IPC cross-swarm route discovery request to {}", jsonData["destAddr"].get<std::string>());
                        initCrossSwarmRouteDiscovery(jsonData["destAddr"].get<std::string>());
                    } else {
                        logger->info("Processing IPC route discovery request to {}", jsonData["destAddr"].get<std::string>());
                        initRouteDiscovery(jsonData["destAddr"].get<std::string>());
                    }
                } else if (messageType == VERIFY_ROUTE) {
                    verifyRouteHandler(jsonData);
                } else if (messageType == INIT_LEAVE) {
                    logger->info("Processing IPC leave request");
                    leaveSwarm();
                }
            }
            if (messageType == HELLO) {
                if (!this->discoveryPhaseActive.load()){
                    logger->warn("Discovery phase inactive, ignoring message");
                    continue;
                }
                initMessageHandler(jsonData);
                continue;
            } else if (messageType == INIT_ROUTE_DISCOVERY) {
                logger->info("Processing route discovery request");
                GCS_MESSAGE ctl;
                ctl.deserialize(jsonData);
                initRouteDiscovery(ctl.destAddr);
                continue;
            } else if (messageType == VERIFY_ROUTE) {
                verifyRouteHandler(jsonData);
                continue;
            }
            // For all other message types, check if sender is validated
            if (!jsonData.contains("srcAddr")) {
                logger->error("Message missing srcAddr field");
                continue;
            }
            std::string srcAddr = jsonData["recvAddr"].get<std::string>();

            // If we have a leader, we check the CRL to determine if the node is valid to parse the message
            // If we don't have a leader, we parse the message anyway
            bool skipValidation = false;

            {
                std::lock_guard<std::mutex> lock(leaderMutex);
                if (this->current_leader.empty() || !this->leaderFunctionalityEnabled) {
                    // No leader or leadership functionality disabled, skip validation and proceed with message
                    logger->debug("No leader present or leadership disabled - processing message without CRL check");
                    skipValidation = true;
                } else {
                    // We have a leader, check the CRL
                    if (isNodeOnCRL(srcAddr)) {
                        logger->warn("Message from revoked node {} rejected - found on CRL", srcAddr);
                        continue; // Skip this message as the node is on the CRL
                    }
                    logger->debug("Node {} OK - proceeding with validation", srcAddr);
                }
            }
            // If skipValidation is true (no leader), we still check for validation but don't reject if not validated
            // If skipValidation is false (have leader), we need both validation and CRL check to pass
            if (!isValidatedSender(srcAddr) && srcAddr != this->addr) {
                try {
                    ChallengeRequest challenge_req;
                    challenge_req.type = CERTIFICATE_VALIDATION;
                    challenge_req.challenge_type = CHALLENGE_REQUEST;
                    challenge_req.srcAddr = this->addr;
                    challenge_req.nonce = static_cast<uint32_t>(std::random_device{}());
                    challenge_req.timestamp = std::chrono::system_clock::now();
                    challenge_req.challenge_data = generateChallengeData();

                    pki_client->storePendingChallenge(srcAddr, challenge_req.challenge_data);

                    logger->debug("Challenge request sent to {}", srcAddr);
                    // continue;
                } catch (const std::exception& e) {
                    logger->error("Failed to create challenge request: {}", e.what());
                    if (!skipValidation) {
                        continue; // Only skip message if validation is required (leader present)
                    }
                }
                if (!this->current_leader.empty() && this->leaderFunctionalityEnabled && !isValidSwarmNode(srcAddr)) {
                    logger->info("Initiating validation for unvalidated sender {}", srcAddr);
                    // Add swarm membership check
                }

                // If skipValidation is true (no leader), allow message processing to continue
                if (skipValidation) {
                    logger->debug("Processing message without validation as no leader is present");
                } else if (!isValidatedSender(srcAddr) && srcAddr != this->addr) {
                    logger->warn("Skipping message from unvalidated sender {} while leader is present", srcAddr);
                    // continue; // Skip if we require validation but node is not validated
                }
            }

            // Process validated messages
            try {
                switch(messageType) {
                    case ROUTE_REQUEST:
                        routeRequestHandler(jsonData);
                        break;
                    case ROUTE_REPLY:
                        routeReplyHandler(jsonData);
                        break;
                    case ROUTE_ERROR:
                        routeErrorHandler(jsonData);
                        break;
                    case DATA:
                        dataHandler(jsonData);
                        break;
                    case LEAVE_NOTIFICATION:
                        leaveHandler(jsonData);
                        break;
                    case JOIN_REQUEST:
                        joinRequestHandler(jsonData);
                        break;
                    case JOIN_RESPONSE:
                        joinResponseHandler(jsonData);
                        break;
                    case EXIT:
                        std::exit(0);
                        break;
                    default:
                        logger->warn("Unrecognized message type");
                        break;
                }
            } catch (const std::exception& e) {
                logger->error("Error processing message: {}", e.what());
            }
        } catch (const json::parse_error& e) {
            logger->error("Failed to parse message: {}", e.what());
            logger->error("Raw message: {}", rawMessage);
        } catch (const std::exception& e) {
            logger->error("Unexpected error: {}", e.what());
        }
    }

    // Cleanup remaining messages when shutting down
    std::lock_guard<std::mutex> lock(queueMutex);
    while (!messageQueue.empty()) {
        messageQueue.pop();
    }
}

void drone::leaveHandler(json& data) {
    try {
        LeaveMessage leave_msg;
        leave_msg.deserialize(data);

        auto now = std::chrono::system_clock::now();
        auto time_diff = std::chrono::duration_cast<std::chrono::seconds>(
            now - leave_msg.timestamp).count();
        if (std::abs(time_diff) > 30) {
            logger->warn("Received expired leave notification from {}", leave_msg.srcAddr);
            return;
        }

        {
            std::lock_guard<std::mutex> lock(routingTableMutex);
            tesla.routingTable.remove(leave_msg.srcAddr);
        }

        {
            std::lock_guard<std::mutex> lock(validationMutex);
            validatedNodes.erase(leave_msg.srcAddr);
        }

        logger->info("Node {} has left the swarm", leave_msg.srcAddr);

    } catch (const std::exception& e) {
        logger->error("Error processing leave notification: {}", e.what());
    }
}

void drone::dataHandler(json& data){
    /*Forwards data to next hop, or passes up to application layer if destination*/
    DATA_MESSAGE msg;
    msg.deserialize(data);

    // Handle case where we are the destination
    if (msg.isBroadcast || (msg.destAddr == this->addr)) {
        logger->info("Received data message for this node");
        return;
    }

    logger->debug("Forwarding data to next hop");
    if (this->tesla.routingTable.find(msg.destAddr)) {
        logger->debug("Route found, sending data");
        auto routeEntry = this->tesla.routingTable.get(msg.destAddr);

        // Check if this is a cross-swarm route
        if (routeEntry->isCrossSwarm) {
            // Check if we have leader information
            if (!routeEntry->targetLeader.empty()) {
                if (this->isLeader) {
                    // We are the leader, so forward to the target leader
                    logger->info("Forwarding cross-swarm data to target leader: {}", routeEntry->targetLeader);

                    // Create a copy with cross-swarm flags
                    DATA_MESSAGE crossMsg = msg;
                    crossMsg.isCrossSwarm = true;
                    crossMsg.forwardingLeader = this->addr;

                    // Sign the message
                    std::vector<uint8_t> dataToSign(msg.destAddr.begin(), msg.destAddr.end());
                    if (pki_client->signMessage(dataToSign)) {
                        std::stringstream ss;
                        for (const auto& byte : dataToSign) {
                            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
                        }
                        crossMsg.leaderSignature = ss.str();
                    }

                    if (sendData(routeEntry->targetLeader, crossMsg.serialize()) != 0) {
                        logger->error("Failed to forward cross-swarm data to target leader");
                    }
                } else {
                    // We are not the leader, so forward to our leader
                    std::lock_guard<std::mutex> lock(leaderMutex);
                    if (!current_leader.empty()) {
                        logger->info("Forwarding cross-swarm data to our leader: {}", current_leader);
                        if (sendData(current_leader, msg.serialize()) != 0) {
                            logger->error("Failed to forward cross-swarm data to our leader");
                        }
                    } else {
                        logger->error("Cannot forward cross-swarm data - no leader available");
                    }
                }
            } else {
                logger->error("Cross-swarm route without target leader information");
            }
        } else {
            // Regular route, forward to next hop
            if (sendData(routeEntry->intermediateAddr, msg.serialize()) != 0) {
                RERR rerr;
                // Attach information here for RERR
                TESLA::nonce_data data = this->tesla.getNonceData(msg.srcAddr);
                rerr.create_rerr(data.nonce, data.tesla_key, data.destination, data.auth);
                rerr.addRetAddr(msg.srcAddr);
                rerr.setSrcAddr(this->addr); // Set source address to current node

                sendData(this->tesla.routingTable.get(msg.srcAddr)->intermediateAddr, rerr.serialize());
            }
        }
    } else {
        // If this is a cross-swarm request and we are a leader, try to handle it
        if (msg.isCrossSwarm && this->isLeader && !msg.forwardingLeader.empty()) {
            logger->info("Received cross-swarm data from leader {}", msg.forwardingLeader);

            // Check if destination is in our swarm
            bool isDestInSwarm = false;
            {
                std::lock_guard<std::mutex> lock(swarmMembersMutex);
                isDestInSwarm = (swarmMembers.find(msg.destAddr) != swarmMembers.end());
            }

            if (isDestInSwarm) {
                // Destination is in our swarm, forward directly
                logger->info("Forwarding cross-swarm data to destination: {}", msg.destAddr);
                if (sendData(msg.destAddr, msg.serialize()) != 0) {
                    logger->error("Failed to forward cross-swarm data to destination");
                }
            } else {
                logger->error("Destination {} not in this swarm", msg.destAddr);
            }
        } else {
            logger->error("No route found for destination: {}", msg.destAddr);
        }
    }
}

void drone::handleIPCMessage(const std::string& message) {
    try {
        // Parse the message as JSON
        json jsonData = json::parse(message);

        // Add a special flag to mark this as coming from IPC
        jsonData["from_ipc"] = true;

        // Add minimal required fields if they don't exist
        if (!jsonData.contains("srcAddr")) {
            jsonData["srcAddr"] = "ipc_client";
        }

        std::lock_guard<std::mutex> lock(queueMutex);
        messageQueue.push(jsonData.dump());
        cv.notify_one();
        logger->debug("Queued IPC message: {}", jsonData.dump());
    } catch (const json::parse_error& e) {
        // If there's a parsing error, still try to handle the raw message
        logger->warn("Failed to parse IPC message as JSON: {}", e.what());
        std::lock_guard<std::mutex> lock(queueMutex);
        messageQueue.push(message);
        cv.notify_one();
    } catch (const std::exception& e) {
        logger->error("Failed to process IPC message: {}", e.what());
    }
}

void drone::broadcast(const std::string& msg) {
    DATA_MESSAGE data("BRDCST", this->addr, msg, true);
    logger->debug("Broadcasting data");
    this->udpInterface.broadcast(data.serialize());
}

bool drone::addPendingRoute(const PendingRoute& route) {
    std::lock_guard<std::mutex> lock(pendingRoutesMutex);

    if (pendingRoutes.size() >= CLEANUP_THRESHOLD) {
        cleanupExpiredRoutes();
    }

    if (pendingRoutes.size() >= MAX_PENDING_ROUTES) {
        logger->warn("Maximum pending routes limit reached. Rejecting route to {}", route.destAddr);
        return false;
    }

    auto it = std::find_if(pendingRoutes.begin(), pendingRoutes.end(),
        [&route](const auto& existing) { return existing.destAddr == route.destAddr; });

    if (it != pendingRoutes.end()) {
        *it = route;
        return true;
    }

    pendingRoutes.push_back(route);
    return true;
}

void drone::cleanupExpiredRoutes() {
    auto now = std::chrono::steady_clock::now();

    // Remove expired routes
    auto newEnd = std::remove_if(pendingRoutes.begin(), pendingRoutes.end(),
        [now](const PendingRoute& route) {
            return now >= route.expirationTime;
        });

    size_t removedCount = std::distance(newEnd, pendingRoutes.end());
    pendingRoutes.erase(newEnd, pendingRoutes.end());

    if (removedCount > 0) {
        logger->debug("Cleaned up {} expired pending routes", removedCount);
    }
}

int drone::send(const string& destAddr, string msg, bool isExternal) {
    logger->debug("Preparing to send data: {}", msg);
    if (isExternal) {
        DATA_MESSAGE data;
        data.destAddr = destAddr;
        data.srcAddr = this->addr;
        data.data = std::move(msg);
        msg = data.serialize();
    }

    // Check if we have a route to the destination
    if (!this->tesla.routingTable.find(destAddr)) {
        logger->info("Route not found, checking if cross-swarm destination");

        // Check if the destination might be in another swarm
        bool isKnownInSwarm = false;
        {
            std::lock_guard<std::mutex> lock(swarmMembersMutex);
            isKnownInSwarm = (swarmMembers.find(destAddr) != swarmMembers.end());
        }

        // If it's not in our swarm and we're in swarm phase, try cross-swarm discovery
        if (!isKnownInSwarm && this->swarmPhase.load()) {
            logger->info("Attempting cross-swarm route discovery for {}", destAddr);

            PendingRoute pendingRoute;
            pendingRoute.destAddr = destAddr;
            pendingRoute.msg = msg;
            pendingRoute.expirationTime = std::chrono::steady_clock::now() +
                                        std::chrono::seconds(this->timeout_sec);

            if (!addPendingRoute(pendingRoute)) {
                logger->error("Failed to queue message for {}", destAddr);
                return -1;
            }

            // Initiate cross-swarm route discovery
            this->initCrossSwarmRouteDiscovery(destAddr);
            return 0;
        } else {
            // Regular route discovery
            logger->info("Route not found, initiating standard route discovery.");
            logger->trace("Destination: {}", destAddr);
            logger->trace("Message: {}", msg);

            PendingRoute pendingRoute;
            pendingRoute.destAddr = destAddr;
            pendingRoute.msg = msg;
            pendingRoute.expirationTime = std::chrono::steady_clock::now() +
                                        std::chrono::seconds(this->timeout_sec);

            if (!addPendingRoute(pendingRoute)) {
                logger->error("Failed to queue message for {}", destAddr);
                return -1;
            }

            this->initRouteDiscovery(destAddr);
        }
    } else {
        // We have a route, check if it's a cross-swarm route
        auto routeEntry = this->tesla.routingTable.get(destAddr);
        if (routeEntry->isCrossSwarm) {
            logger->info("Using existing cross-swarm route via leader {}", routeEntry->targetLeader);

            // For cross-swarm routes, we need to prepare a cross-swarm data message
            if (isExternal) {
                // Already serialized as a DATA_MESSAGE above, deserialize to modify
                DATA_MESSAGE data;
                auto parsedJson = json::parse(msg);
                data.deserialize(parsedJson);
                data.isCrossSwarm = true;

                // If we're a leader, set forwarding leader and sign
                if (this->isLeader) {
                    data.forwardingLeader = this->addr;

                    // Sign the message
                    std::vector<uint8_t> dataToSign(data.destAddr.begin(), data.destAddr.end());
                    if (pki_client->signMessage(dataToSign)) {
                        std::stringstream ss;
                        for (const auto& byte : dataToSign) {
                            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
                        }
                        data.leaderSignature = ss.str();
                    }

                    msg = data.serialize();
                }
            }

            // Send to appropriate next hop based on our role
            if (this->isLeader) {
                // Leaders send directly to the target leader
                return sendData(routeEntry->targetLeader, msg);
            } else {
                // Regular nodes send to their leader
                std::lock_guard<std::mutex> lock(leaderMutex);
                if (!current_leader.empty()) {
                    return sendData(current_leader, msg);
                } else {
                    logger->error("Cannot send cross-swarm message - no leader available");
                    return -1;
                }
            }
        } else {
            // Regular route, use normal next hop
            return sendData(routeEntry->intermediateAddr, msg);
        }
    }

    return 0;
}

void drone::processPendingRoutes() {
    std::vector<PendingRoute> routesToProcess;

    {
        std::lock_guard<std::mutex> lock(pendingRoutesMutex);
        // Clean up expired routes first
        cleanupExpiredRoutes();

        // Move routes to temporary vector for processing
        routesToProcess.reserve(pendingRoutes.size());
        for (const auto& route : pendingRoutes) {
            routesToProcess.push_back(route);
        }
        pendingRoutes.clear();
    }

    auto now = std::chrono::steady_clock::now();

    for (const auto& route : routesToProcess) {
        if (now >= route.expirationTime) {
            logger->debug("Route to {} expired, dropping message", route.destAddr);
            continue;
        }

        if (this->tesla.routingTable.find(route.destAddr)) {
            if (sendData(this->tesla.routingTable.get(route.destAddr)->intermediateAddr,
                        route.msg) != 0) {
                logger->error("Failed to send message to {}, re-queueing", route.destAddr);
                addPendingRoute(route);
            }
        } else {
            // Route still not found, but not expired - re-queue
            addPendingRoute(route);
        }
    }
}

void drone::routeErrorHandler(json& data){
    try {
        RERR msg;
        msg.deserialize(data);

        // Get destination from first element
        string destination = msg.dst_list[0];
        string nonce = msg.nonce_list[0];
        // string auth = msg.auth_list[0];
        string tsla_key = msg.tsla_list[0];

        logger->info("Received RERR for destination: {}", destination);

        // Check if we have a routing table entry for this destination
        if (!this->tesla.routingTable.find(destination)) {
            logger->warn("No routing table entry found for destination: {}", destination);
            return;
        }


        logger->info("All saved info: ");
        this->tesla.routingTable[msg.retAddr].print();
        try {
            string table_tesla_key = this->tesla.routingTable[msg.retAddr].getTeslaKey();

            // Create RERR_prime for verification
            RERR rerr_prime;
            rerr_prime.create_rerr_prime(nonce, destination, tsla_key);

            bool verification_result = (tsla_key == table_tesla_key);
            // compute hash over RERR afterwards if tesla keys match

            if (verification_result) {
                logger->info("TESLA Verification SUCCESSFUL for destination: {}", destination);

                try {
                    // Propagate RERR upstream
                    // TESLA::nonce_data upstream_data = this->tesla.getNonceData(msg.retAddr);
                    // msg.create_rerr(upstream_data.nonce, upstream_data.tesla_key,
                    //               upstream_data.destination, upstream_data.auth);
                    // msg.setSrcAddr(this->addr); // Set source address to current node

                    // Send to next hop
                    auto next_hop = this->tesla.routingTable.get(msg.retAddr)->intermediateAddr;
                    logger->info("Propagating RERR to: {}", next_hop);
                    if (next_hop == this->addr) {
                        sendData(msg.retAddr, msg.serialize());
                    } else {
                        sendData(next_hop, msg.serialize());
                    }

                    // Remove entry from routing table
                    {
                        std::lock_guard<std::mutex> rtLock(routingTableMutex);
                        logger->info("Removing routing table entry for: {}", msg.retAddr);
                        this->tesla.routingTable.remove(msg.retAddr);
                    }
                } catch (std::runtime_error& e) {
                    logger->info("End of RERR backpropagation reached: {}", e.what());
                }
            } else {
                logger->error("TESLA Verification FAILED for destination: {}", destination);
            }
        } catch (std::runtime_error& e) {
            logger->error("Error retrieving HERR from routing table: {}", e.what());
        }
    } catch (const std::exception& e) {
        logger->error("Exception in routeErrorHandler: {}", e.what());
    }
}

void drone::verifyRouteHandler(json& data){
    this->tesla.routingTable.print();
    this->tesla.printNonceMap();
}

int drone::sendData(string containerName, const string& msg) {
    logger->debug("Attempting to connect to {} on port {}", containerName, this->port);
    TCPInterface clientSocket(0, false); // 0 for port, false for is_server
    if (clientSocket.connect_to(containerName, this->port) == -1) {
        logger->error("Error connecting to {}", containerName);
        return -1;
    }

    logger->debug("Sending data: {}", msg);

    if (clientSocket.send_data(msg) == -1) {
        logger->error("Error sending data to {}", containerName);
        return -1;
    }
    logger->info("Data sent to {}", containerName);
    return 0;
}

string drone::getHashFromChain(unsigned long seqNum, unsigned long hopCount) {
    size_t index = ((seqNum - 1) * this->max_hop_count) + hopCount;

    if (index >= hashChainCache.size()) {
        logger->error("Hash chain access out of bounds: {} >= {}",
                        index, hashChainCache.size());
        throw std::out_of_range("Hash chain index out of bounds");
    }

    return hashChainCache[index];
}

void drone::initRouteDiscovery(const string& destAddr){
    /* Constructs an RREQ and broadcast to neighbors
    It is worth noting that routes may sometimes be incorrectly not found because a routing table clear may occur during the route discovery process. To mitagate this issue, we can try any or all of the following: 1) Retry the route discovery process X times before giving up. 2) Increase the amount of time before a routing table clear occurs (Currently at 30 seconds). Check github issue for full description.
    */
    std::unique_ptr<RREQ> msg = std::make_unique<RREQ>();
    msg->type = ROUTE_REQUEST; msg->srcAddr = this->addr; msg->recvAddr = this->addr;
    msg->destAddr = destAddr; msg->srcSeqNum = ++this->seqNum; msg->ttl = this->max_hop_count; 
    msg->tsla_key = this->tesla.getCurrentHash();
    msg->destSeqNum = [&]() {
        std::lock_guard<std::mutex> lock(this->routingTableMutex);
        auto it = this->tesla.routingTable.get(msg->destAddr);
        return (it) ? it->seqNum : 0;
    }();

    msg->hopCount = 1;
    try {
        msg->hash = (msg->srcSeqNum == 1) ? getHashFromChain(1, 1) : getHashFromChain(msg->srcSeqNum, 1);
    } catch (const std::out_of_range& e) {
        logger->error("Hash chain access error: {}", e.what());
        return;
    }

    HashTree tree = HashTree(msg->srcAddr);
    msg->hashTree = tree.toVector();
    msg->rootHash = tree.getRoot()->hash;
    msg->tsla_key = this->tesla.getCurrentHash();

    // RERR rerr_prime;
    // string nonce = generate_nonce(), tsla_hash = this->tesla.getCurrentHash();
    // rerr_prime.create_rerr_prime(nonce, msg->srcAddr, msg->hash);
    // rerr_prime.setSrcAddr(this->addr); // Set source address to current node
    // msg->herr = HERR::create(rerr_prime, tsla_hash);

    // this->tesla.insert(msg->destAddr, TESLA::nonce_data{nonce, tsla_hash, msg->hash, msg->srcAddr});
    PendingRoute pendingRoute;
    pendingRoute.destAddr = destAddr;
    pendingRoute.expirationTime = std::chrono::steady_clock::now() +
                                std::chrono::seconds(this->timeout_sec);
    if (!addPendingRoute(pendingRoute)) {
        logger->error("Failed to queue route discovery for {}", destAddr);
        return;
    }
    string buf = msg->serialize();
    logger->info("Serialized message size: {} bytes", buf.size());
    udpInterface.broadcast(buf);
}

void drone::initCrossSwarmRouteDiscovery(const string& destAddr) {
    logger->info("Initiating cross-swarm route discovery to {}", destAddr);

    // First check if we are the leader
    if (this->isLeader) {
        // As a leader, create an RREQ packet with cross-swarm flag
        std::unique_ptr<RREQ> msg = std::make_unique<RREQ>();
        msg->type = ROUTE_REQUEST;
        msg->srcAddr = this->addr;
        msg->recvAddr = this->addr;
        msg->destAddr = destAddr;
        msg->srcSeqNum = ++this->seqNum;
        msg->ttl = this->max_hop_count;
        msg->isCrossSwarm = true; // Mark as cross-swarm request
        msg->forwardingLeader = this->addr; // This leader is forwarding
        msg->tsla_key = this->tesla.getCurrentHash();

        msg->destSeqNum = [&]() {
            std::lock_guard<std::mutex> lock(this->routingTableMutex);
            auto it = this->tesla.routingTable.get(msg->destAddr);
            return (it) ? it->seqNum : 0;
        }();

        msg->hopCount = 1;
        try {
            msg->hash = (msg->srcSeqNum == 1) ? getHashFromChain(1, 1) : getHashFromChain(msg->srcSeqNum, 1);
        } catch (const std::out_of_range& e) {
            logger->error("Hash chain access error: {}", e.what());
            return;
        }

        HashTree tree = HashTree(msg->srcAddr);
        msg->hashTree = tree.toVector();
        msg->rootHash = tree.getRoot()->hash;

        // RERR rerr_prime;
        // string nonce = generate_nonce(), tsla_hash = this->tesla.getCurrentHash();
        // rerr_prime.create_rerr_prime(nonce, msg->srcAddr, msg->hash);
        // msg->herr = HERR::create(rerr_prime, tsla_hash);

        // Sign the message to authenticate between leaders
        std::vector<uint8_t> dataToSign(msg->destAddr.begin(), msg->destAddr.end());
        if (!pki_client->signMessage(dataToSign)) {
            logger->error("Failed to sign cross-swarm RREQ");
            return;
        }

        std::stringstream ss;
        for (const auto& byte : dataToSign) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        msg->leaderSignature = ss.str();

        // this->tesla.insert(msg->destAddr, TESLA::nonce_data{nonce, tsla_hash, msg->hash, msg->srcAddr});

        // Add pending route entry
        PendingRoute pendingRoute;
        pendingRoute.destAddr = destAddr;
        pendingRoute.expirationTime = std::chrono::steady_clock::now() +
                                    std::chrono::seconds(this->timeout_sec);
        if (!addPendingRoute(pendingRoute)) {
            logger->error("Failed to queue cross-swarm route discovery for {}", destAddr);
            return;
        }

        // Serialize and broadcast to other leaders
        string buf = msg->serialize();
        logger->info("Broadcasting cross-swarm RREQ to other leaders");
        broadcastToOtherLeaders(buf, this->addr);
    } else {
        // Regular node - forward request to our leader
        std::lock_guard<std::mutex> lock(leaderMutex);
        if (current_leader.empty()) {
            logger->error("Cannot initiate cross-swarm route discovery - no leader available");
            return;
        }

        // Create a standard RREQ but mark it for the leader to handle as cross-swarm
        std::unique_ptr<RREQ> msg = std::make_unique<RREQ>();
        msg->type = ROUTE_REQUEST;
        msg->srcAddr = this->addr;
        msg->recvAddr = this->addr;
        msg->destAddr = destAddr;
        msg->srcSeqNum = ++this->seqNum;
        msg->ttl = this->max_hop_count;
        msg->isCrossSwarm = true; // Mark as cross-swarm request, but don't set forwarding leader

        msg->destSeqNum = [&]() {
            std::lock_guard<std::mutex> lock(this->routingTableMutex);
            auto it = this->tesla.routingTable.get(msg->destAddr);
            return (it) ? it->seqNum : 0;
        }();

        msg->hopCount = 1;
        try {
            msg->hash = (msg->srcSeqNum == 1) ? getHashFromChain(1, 1) : getHashFromChain(msg->srcSeqNum, 1);
        } catch (const std::out_of_range& e) {
            logger->error("Hash chain access error: {}", e.what());
            return;
        }

        HashTree tree = HashTree(msg->srcAddr);
        msg->hashTree = tree.toVector();
        msg->rootHash = tree.getRoot()->hash;
        msg->tsla_key = this->tesla.getCurrentHash();

        // RERR rerr_prime;
        // string nonce = generate_nonce(), tsla_hash = this->tesla.getCurrentHash();
        // rerr_prime.create_rerr_prime(nonce, msg->srcAddr, msg->hash);
        // msg->herr = HERR::create(rerr_prime, tsla_hash);
        // this->tesla.insert(msg->destAddr, TESLA::nonce_data{nonce, tsla_hash, msg->hash, msg->srcAddr});

        // Add pending route entry
        PendingRoute pendingRoute;
        pendingRoute.destAddr = destAddr;
        pendingRoute.expirationTime = std::chrono::steady_clock::now() +
                                    std::chrono::seconds(this->timeout_sec);
        if (!addPendingRoute(pendingRoute)) {
            logger->error("Failed to queue cross-swarm route discovery for {}", destAddr);
            return;
        }

        // Send directly to the leader instead of broadcasting
        string buf = msg->serialize();
        logger->info("Sending cross-swarm RREQ to leader {}", current_leader);
        sendData(current_leader, buf);
    }
}

void drone::initMessageHandler(json& data) {
    /*Creates a routing table entry for each authenticator & tesla msg received*/
    // std::lock_guard<std::mutex> lock(this->helloRecvTimerMutex);
    // if (std::chrono::duration_cast<std::chrono::seconds>(
    //     std::chrono::steady_clock::now() - helloRecvTimer).count() > helloRecvTimeout) {
    //     return;
    // }

    INIT_MESSAGE msg;
    msg.deserialize(data);
    logger->debug("HELLO from {} @ {:%H:%M:%S}", msg.srcAddr, std::chrono::system_clock::now());

    if (msg.mode == INIT_MESSAGE::TESLA) {
        logger->debug("Inserting tesla info into routing table.");
        this->tesla.routingTable[msg.srcAddr].setTeslaInfo(msg.hash,
            std::chrono::seconds(msg.disclosure_time));
        this->tesla.routingTable[msg.srcAddr].print();
    } else if (msg.mode == INIT_MESSAGE::LEADER) {
        {
            std::lock_guard<std::mutex> lock(leaderMutex);
            this->current_leader = msg.srcAddr;
        }
        logger->info("Received leader announcement from {}: isLeader={}",
                    msg.srcAddr, msg.is_leader);
    } else {
        std::lock_guard<std::mutex> rtLock(this->routingTableMutex);
        this->tesla.routingTable.insert(msg.srcAddr,
            ROUTING_TABLE_ENTRY(msg.srcAddr, msg.srcAddr, 0, 1,
                std::chrono::system_clock::now(), msg.hash));
    }
}

std::vector<uint8_t> drone::generateChallengeData(size_t length) {
    std::vector<uint8_t> data(length);
    if (RAND_bytes(data.data(), length) != 1) {
        throw std::runtime_error("Failed to generate random challenge data");
    }
    return data;
}


bool drone::isValidatedSender(const std::string& senderAddr) {
    std::lock_guard<std::mutex> lock(this->validationMutex);
    return validatedNodes.find(senderAddr) != validatedNodes.end();
}

void drone::markSenderAsValidated(const std::string& senderAddr) {
    {
        std::lock_guard<std::mutex> lock(this->validationMutex);
        validatedNodes.insert(senderAddr);
        logger->info("Sender {} marked as validated", senderAddr);
    }
}

bool drone::isNodeOnCRL(const std::string& nodeAddr) {
    if (!this->pki_client) {
        logger->error("PKI client not initialized");
        return false;
    }

    try {
        // Check certificate info
        std::string certificate;
        {
            std::lock_guard<std::mutex> lock(networkNodesMutex);
            auto it = networkNodes.find(nodeAddr);
            if (it == networkNodes.end()) {
                logger->debug("Node {} not found in network nodes list", nodeAddr);
                return false; // If we don't know about this node, assume it's not on CRL
            }
            certificate = it->second.certificate;
        }

        // Check cache first
        {
            std::lock_guard<std::mutex> cacheLock(crlCacheMutex);

            // Check if we have a valid cache entry
            auto now = std::chrono::steady_clock::now();
            bool cacheValid = crlCacheLastRefreshed != std::chrono::steady_clock::time_point() &&
                             (now - crlCacheLastRefreshed) < crlCacheLifetime;

            if (cacheValid) {
                auto cacheIt = crlCache.find(certificate);
                if (cacheIt != crlCache.end()) {
                    logger->debug("Using cached CRL status for node {}: {}",
                                 nodeAddr, cacheIt->second ? "revoked" : "valid");
                    return cacheIt->second;
                }
            }
        }

        // Cache miss or expired, need to check with GCS
        httplib::Client client(this->GCS_IP, 5000);
        client.set_connection_timeout(2); // Shorter timeout for demo purposes

        auto res = client.Get("/check_crl/" + certificate);
        if (!res) {
            // Connection failed
            logger->warn("Could not connect to GCS for CRL check of node {}, allowing connection for demo", nodeAddr);
            return false; // Allow connection for demo purposes
        }

        if (res->status != 200) {
            // For demo purposes, we'll allow connections regardless of error type
            if (res->status == 404) {
                logger->warn("CRL check endpoint not found for node {}, allowing connection for demo", nodeAddr);
            } else {
                logger->warn("Failed CRL status check for node {}: HTTP {}, allowing connection for demo",
                            nodeAddr, res->status);
            }
            return false; // Allow connection for demo purposes
        }

        // Update cache with result
        json response = json::parse(res->body);
        bool is_revoked = response.value("revoked", false);

        {
            std::lock_guard<std::mutex> cacheLock(crlCacheMutex);
            crlCache[certificate] = is_revoked;
            crlCacheLastRefreshed = std::chrono::steady_clock::now();

            if (is_revoked) {
                logger->warn("Certificate for node {} is revoked", nodeAddr);
            }
        }

        return is_revoked;
    } catch (const std::exception& e) {
        logger->error("Error checking CRL for node {}: {}", nodeAddr, e.what());
        return false; // Allow connection for demo purposes
    }
}

void drone::routeRequestHandler(json& data){
    /*
    Conditions checked before forwarding:
    1) If the srcAddr is the same as the current node, drop the packet (To be removed in testing)
    2) If the seqNum is less than the seqNum already received, drop the packet
    3a) Calculate hash based on hopCount * seqNum (comparison with routing table is optional because of hash tree)
    3b) Calculate hashTree where lastElement = H[droneName || hash] (hash = hashIterations * baseHash) (hashIterations = hopCount * seqNum)
    */
    auto start_time = std::chrono::high_resolution_clock::now();
    size_t bytes_sent = 0;  // Track total bytes sent
    logger->debug("=== Starting RREQ Handler ===");
    try {
        std::lock_guard<std::mutex> lock(this->routingTableMutex);
        RREQ msg;

        msg.deserialize(data);

        logger->debug("RREQ Details - SrcAddr: {}, DestAddr: {}, HopCount: {}",
                     msg.srcAddr, msg.destAddr, msg.hopCount);

        // Check if this is a cross-swarm RREQ that needs special handling
        if (msg.isCrossSwarm) {
            // Only leaders can process cross-swarm requests from other leaders
            if (this->isLeader && !msg.forwardingLeader.empty() && msg.forwardingLeader != this->addr) {
                logger->info("Received cross-swarm RREQ from leader {}", msg.forwardingLeader);
                handleCrossSwarmRREQ(data);
                return;
            }

            // If we're not a leader but received a cross-swarm request, forward to our leader
            if (!this->isLeader && msg.forwardingLeader.empty()) {
                std::lock_guard<std::mutex> leaderLock(leaderMutex);
                if (!current_leader.empty()) {
                    logger->info("Forwarding cross-swarm RREQ to leader {}", current_leader);
                    sendData(current_leader, data.dump());
                    return;
                }
            }

            // If this is a cross-swarm request without a forwarding leader, and we are a leader,
            // it's from one of our swarm members - need to handle it
            if (this->isLeader && msg.forwardingLeader.empty()) {
                // Handle the request from our swarm member
                logger->info("Received cross-swarm RREQ from swarm member {}", msg.srcAddr);

                // Sign the message
                std::vector<uint8_t> dataToSign(msg.destAddr.begin(), msg.destAddr.end());
                if (!pki_client->signMessage(dataToSign)) {
                    logger->error("Failed to sign cross-swarm RREQ from swarm member");
                    return;
                }

                std::stringstream ss;
                for (const auto& byte : dataToSign) {
                    ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
                }

                // Update the message with leader information
                msg.forwardingLeader = this->addr;
                msg.leaderSignature = ss.str();

                // Broadcast to other leaders
                string buf = msg.serialize();
                logger->info("Broadcasting cross-swarm RREQ to other leaders");
                broadcastToOtherLeaders(buf, this->addr);
                return;
            }
        }

        if (msg.srcAddr == this->addr) {
            logger->debug("Dropping RREQ: Source address matches current node");
            return;
        }

        if (msg.hashTree.empty()) {
            logger->error("Invalid RREQ: Empty hash tree");
            return;
        }

        logger->debug("Checking routing table entries");
        if (this->tesla.routingTable.find(msg.srcAddr)) {
            logger->debug("Found routing entries for src and recv addresses");

            if (msg.srcSeqNum <= this->tesla.routingTable.get(msg.srcAddr)->seqNum) {
                logger->warn("Dropping RREQ: Smaller sequence number");
                logger->warn("Received seqNum: {}, Current seqNum: {}",
                            msg.srcSeqNum, this->tesla.routingTable.get(msg.srcAddr)->seqNum);
                return;
            }

            string hashRes = msg.hash;
            int hashIterations = (this->max_hop_count * (msg.srcSeqNum > 0 ? msg.srcSeqNum - 1 : 0)) + msg.hopCount;

            logger->debug("Calculating hash iterations: {}", hashIterations); // TODO: Change back to debug
            for (int i = 0; i < hashIterations; i++) {
                hashRes = sha256(hashRes);
                logger->debug("Hash iteration {}: {}", i, hashRes);
            }

            if (this->tesla.routingTable.find(msg.recvAddr)) {
                if (hashRes != this->tesla.routingTable.get(msg.recvAddr)->hash) {
                    logger->error("Hash verification failed");
                    logger->error("Expected: {}", this->tesla.routingTable.get(msg.recvAddr)->hash);
                    logger->error("Calculated: {}", hashRes);
                    return;
                }
            }

            if (msg.ttl <= 0) {
                logger->warn("Dropping RREQ: TTL exceeded");
                return;
            }

            if (msg.hopCount >= this->max_hop_count) {
                logger->debug("Dropping RREQ: Maximum hop count reached");
                return;
            }
        }

        std::unique_ptr<HashTree> tree;
        try {
            tree = std::make_unique<HashTree>(msg.hashTree, msg.hopCount, msg.recvAddr);

            logger->debug("Verifying HashTree");
            if (!tree->verifyTree(msg.rootHash)) {
                logger->error("HashTree verification failed - Root hash mismatch");
                logger->debug("Expected root hash: {}", msg.rootHash);
                logger->debug("Calculated root hash: {}", tree->getRoot()->hash);
                return;
            }
        } catch (const std::exception& e) {
            logger->error("Failed to create/verify HashTree: {}", e.what());
            return;
        }

        // Check if we're the destination
        if (msg.destAddr == this->addr) {
            logger->info("This node is the destination, preparing RREP");
            try {
                RREP rrep;
                rrep.srcAddr = this->addr;
                rrep.destAddr = msg.srcAddr;
                rrep.recvAddr = this->addr;
                rrep.srcSeqNum = this->seqNum;

                // If this was a cross-swarm request, mark the reply as cross-swarm too
                rrep.isCrossSwarm = msg.isCrossSwarm;
                if (msg.isCrossSwarm && !msg.forwardingLeader.empty()) {
                    rrep.forwardingLeader = this->addr; // For replies, use our address as forwarding leader

                    // Sign the message if we are the leader
                    if (this->isLeader) {
                        std::vector<uint8_t> dataToSign(msg.srcAddr.begin(), msg.srcAddr.end());
                        if (pki_client->signMessage(dataToSign)) {
                            std::stringstream ss;
                            for (const auto& byte : dataToSign) {
                                ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
                            }
                            rrep.leaderSignature = ss.str();
                        }
                    }
                }

                if (this->tesla.routingTable.find(msg.destAddr)) {
                    rrep.destSeqNum = this->tesla.routingTable.get(msg.destAddr)->seqNum;
                } else {
                    rrep.destSeqNum = this->seqNum;
                    logger->debug("Creating new routing table entry");
                    // Create a routing table entry with cross-swarm info if needed
                    if (msg.isCrossSwarm && !msg.forwardingLeader.empty()) {
                        this->tesla.routingTable.insert(msg.srcAddr,
                            ROUTING_TABLE_ENTRY(msg.srcAddr, msg.recvAddr, msg.srcSeqNum, 0,
                            std::chrono::system_clock::now(), "", true, msg.forwardingLeader, msg.tsla_key));
                    } else {
                        this->tesla.routingTable.insert(msg.srcAddr,
                            ROUTING_TABLE_ENTRY(msg.srcAddr, msg.recvAddr, msg.srcSeqNum, 0,
                            std::chrono::system_clock::now(), "", msg.tsla_key));
                    }
                }

                rrep.hopCount = 1;
                rrep.hash = (this->seqNum == 1) ?
                    getHashFromChain(1, 1) :
                    getHashFromChain(this->seqNum, 1);

                // RERR rerr_prime;
                // string nonce = generate_nonce();
                // string tsla_hash = this->tesla.getCurrentHash();

                // logger->debug("Creating RERR prime with nonce");
                // rerr_prime.create_rerr_prime(nonce, rrep.srcAddr, rrep.hash);
                // rrep.herr = HERR::create(rerr_prime, tsla_hash);

                // this->tesla.insert(rrep.destAddr,
                //     TESLA::nonce_data{nonce, tsla_hash, rrep.hash, rrep.srcAddr});
                rrep.tsla_key = this->tesla.getCurrentHash();

                string buf = rrep.serialize();
                logger->info("Sending RREP: {}", buf);
                bytes_sent += buf.size();

                if (msg.isCrossSwarm && !msg.forwardingLeader.empty() && this->isLeader) {
                    // If this is a cross-swarm response and we're a leader, send to the forwarding leader
                    logger->info("Sending cross-swarm RREP to forwarding leader: {}", msg.forwardingLeader);
                    sendData(msg.forwardingLeader, buf);
                } else if (msg.hopCount == 1) {
                    sendData(rrep.destAddr, buf);
                } else {
                    auto nextHop = this->tesla.routingTable.get(msg.srcAddr)->intermediateAddr;
                    logger->info("Sending RREP to next hop: {}", nextHop);
                    sendData(nextHop, buf);
                }
            } catch (const std::exception& e) {
                logger->error("Exception while creating RREP: {}", e.what());
                return;
            }
        } else {
            logger->debug("Forwarding RREQ");
            try {
                msg.hopCount++;
                msg.ttl--;

                std::string addrToDest;
                if (auto routeEntry = this->tesla.routingTable.get(msg.destAddr)) {
                    msg.destSeqNum = routeEntry->seqNum;
                    addrToDest = routeEntry->intermediateAddr;
                } else {
                    msg.destSeqNum = this->seqNum;
                }

                logger->debug("Inserting routing table entry");
                // Include cross-swarm info if this is a cross-swarm request
                if (msg.isCrossSwarm && !msg.forwardingLeader.empty()) {
                    this->tesla.routingTable.insert(msg.srcAddr,
                        ROUTING_TABLE_ENTRY(msg.srcAddr, msg.recvAddr, msg.srcSeqNum,
                        msg.hopCount, std::chrono::system_clock::now(), "",
                        true, msg.forwardingLeader, msg.tsla_key));
                } else {
                    this->tesla.routingTable.insert(msg.srcAddr,
                        ROUTING_TABLE_ENTRY(msg.srcAddr, msg.recvAddr, msg.srcSeqNum,
                        msg.hopCount, std::chrono::system_clock::now(), "", msg.tsla_key));
                }

                msg.hash = (msg.srcSeqNum == 1) ?
                    getHashFromChain(1, msg.hopCount) :
                    this->hashChainCache[(msg.srcSeqNum - 1) * (this->max_hop_count) + msg.hopCount];

                logger->debug("Updating HashTree");
                tree->addSelf(this->addr, msg.hopCount);
                msg.hashTree = tree->toVector();
                msg.rootHash = tree->getRoot()->hash;

                // RERR rerr_prime;
                // string nonce = generate_nonce();
                // string tsla_hash = this->tesla.getCurrentHash();
                // rerr_prime.create_rerr_prime(nonce, msg.srcAddr, msg.hash);
                // msg.herr = HERR::create(rerr_prime, tsla_hash);
                // this->tesla.insert(msg.destAddr,
                //     TESLA::nonce_data{nonce, tsla_hash, msg.hash, msg.srcAddr});

                msg.tsla_key = this->tesla.getCurrentHash();
                msg.recvAddr = this->addr;
                string buf = msg.serialize();
                bytes_sent += buf.size();
                logger->debug("Broadcasting updated RREQ");

                // Try to send through intermediate addr on routing table before broadcasting:
                if (trigger_rerr && !addrToDest.empty()) {
                    if (sendData(addrToDest, buf) != 0) {
                        logger->info("Failed to send to intermediateAddr. Broadcasting RREQ.");
                        udpInterface.broadcast(buf);
                        // generate RERR
                        RERR rerr;
                        std::string data = generate_nonce();
                        string current_tesla_key = this->tesla.getCurrentHash();
                        rerr.create_rerr_prime(data, msg.srcAddr, current_tesla_key);
                        rerr.addRetAddr(msg.srcAddr);
                        rerr.setSrcAddr(this->addr);

                        logger->info("RERR prime created with nonce: {}, destination: {}}",
                                    data, msg.srcAddr);
                        HERR test_herr = HERR::create(rerr, current_tesla_key);
                        logger->info("SENDER: Tesla key: {}", current_tesla_key);
                        logger->info("SENDER - Expected HERR hash: {}", test_herr.hRERR);
                        logger->info("SENDER - Expected HERR mac: {}", test_herr.mac_t);

                        /*Todo: Remove from table*/
                        sendData(this->tesla.routingTable.get(msg.srcAddr)->intermediateAddr, rerr.serialize());
                        udpInterface.broadcast(buf);
                    }
                } else {
                    logger->info("Trigger RERR disabled or No route to destAddr found. Broadcasting RREQ.");
                    udpInterface.broadcast(buf);
                }
            } catch (const std::exception& e) {
                logger->error("Exception while forwarding RREQ: {}", e.what());
                return;
            }
        }
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);

        logger->info("RREQ metrics - Processing time: {} μs, Bytes sent: {}, Source Address: {}, Sequence Number: {}",
                    duration.count(), bytes_sent, msg.srcAddr, msg.srcSeqNum);
        logger->debug("=== Finished RREQ Handler ===");
    } catch (const std::exception& e) {
        logger->error("Critical error in routeRequestHandler: {}", e.what());
    }
}

void drone::handleCrossSwarmRREQ(json& data) {
    try {
        RREQ msg;
        msg.deserialize(data);

        logger->info("Handling cross-swarm RREQ from leader {} for destination {}",
                    msg.forwardingLeader, msg.destAddr);

        // Verify the leader's signature
        // In a real implementation, this would use the leader's public key
        // For now, we just check that there is a signature
        if (msg.leaderSignature.empty()) {
            logger->error("Invalid cross-swarm RREQ: Missing leader signature");
            return;
        }

        // Check if the destination node is in our swarm
        bool isDestInSwarm = false;
        {
            std::lock_guard<std::mutex> lock(swarmMembersMutex);
            isDestInSwarm = (swarmMembers.find(msg.destAddr) != swarmMembers.end()) ||
                          (msg.destAddr == this->addr);
        }

        if (!isDestInSwarm) {
            logger->info("Destination {} not in this swarm, forwarding to other leaders", msg.destAddr);
            // Forward to other leaders
            broadcastToOtherLeaders(data.dump(), msg.forwardingLeader);
            return;
        }

        logger->info("Destination {} found in our swarm, forwarding RREQ", msg.destAddr);

        // The destination is in our swarm, create a special routing table entry for the source node
        // that points back to the leader of the other swarm
        {
            std::lock_guard<std::mutex> lock(routingTableMutex);
            this->tesla.routingTable.insert(msg.srcAddr,
                ROUTING_TABLE_ENTRY(msg.srcAddr, msg.forwardingLeader, msg.srcSeqNum,
                msg.hopCount, std::chrono::system_clock::now(), "",
                true, msg.forwardingLeader, msg.tsla_key));
        }

        // Forward the RREQ to the destination node in our swarm
        if (msg.destAddr == this->addr) {
            // We are the destination, create an RREP
            RREP rrep;
            rrep.srcAddr = this->addr;
            rrep.destAddr = msg.srcAddr;
            rrep.recvAddr = this->addr;
            rrep.srcSeqNum = this->seqNum;
            rrep.isCrossSwarm = true;
            rrep.forwardingLeader = this->addr;

            // Sign the response
            std::vector<uint8_t> dataToSign(msg.srcAddr.begin(), msg.srcAddr.end());
            if (!pki_client->signMessage(dataToSign)) {
                logger->error("Failed to sign cross-swarm RREP");
                return;
            }

            std::stringstream ss;
            for (const auto& byte : dataToSign) {
                ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
            }
            rrep.leaderSignature = ss.str();

            rrep.hopCount = 1;
            rrep.hash = (this->seqNum == 1) ?
                getHashFromChain(1, 1) :
                getHashFromChain(this->seqNum, 1);

            // RERR rerr_prime;
            // string nonce = generate_nonce();
            // string tsla_hash = this->tesla.getCurrentHash();
            // rerr_prime.create_rerr_prime(nonce, rrep.srcAddr, rrep.hash);
            // rrep.herr = HERR::create(rerr_prime, tsla_hash);

            // this->tesla.insert(rrep.destAddr,
            //     TESLA::nonce_data{nonce, tsla_hash, rrep.hash, rrep.srcAddr});

            rrep.tsla_key = this->tesla.getCurrentHash();
            string buf = rrep.serialize();
            logger->info("Sending cross-swarm RREP to leader: {}", msg.forwardingLeader);
            sendData(msg.forwardingLeader, buf);
        } else {
            // Forward to the destination node in our swarm
            logger->info("Forwarding cross-swarm RREQ to destination: {}", msg.destAddr);
            sendData(msg.destAddr, data.dump());
        }
    } catch (const std::exception& e) {
        logger->error("Error handling cross-swarm RREQ: {}", e.what());
    }
}

void drone::routeReplyHandler(json& data) {
    auto start_time = std::chrono::high_resolution_clock::now();
    size_t bytes_sent = 0;
    logger->debug("=== Starting RREP Handler ===");
    try {
        logger->debug("Handling RREP payload: {}", data.dump());
        std::lock_guard<std::mutex> lock(this->routingTableMutex);
        RREP msg;

        msg.deserialize(data);

        logger->debug("RREP Details - SrcAddr: {}, DestAddr: {}, HopCount: {}, SeqNum: {}",
                     msg.srcAddr, msg.destAddr, msg.hopCount, msg.srcSeqNum);

        // Check if this is a cross-swarm RREP that needs special handling
        if (msg.isCrossSwarm) {
            // Only leaders can process cross-swarm replies from other leaders
            if (this->isLeader && !msg.forwardingLeader.empty() && msg.forwardingLeader != this->addr) {
                logger->info("Received cross-swarm RREP from leader {}", msg.forwardingLeader);
                handleCrossSwarmRREP(data);
                return;
            }

            // If we're not a leader but received a cross-swarm reply, forward to our leader
            if (!this->isLeader && msg.forwardingLeader.empty()) {
                std::lock_guard<std::mutex> leaderLock(leaderMutex);
                if (!current_leader.empty()) {
                    logger->info("Forwarding cross-swarm RREP to leader {}", current_leader);
                    sendData(current_leader, data.dump());
                    return;
                }
            }
        }

        // Validate message fields
        if (msg.hash.empty()) {
            logger->error("Invalid RREP: Empty hash");
            return;
        }

        // Check if we have routing table entries for validation
        logger->debug("Checking routing table entries for addr: {}", msg.recvAddr);
        if (!this->tesla.routingTable.find(msg.recvAddr)) {
            logger->error("No routing table entry found for receiver address");
            return;
        }

        // Hash verification
        string hashRes = msg.hash;
        int hashIterations = (this->max_hop_count * (msg.srcSeqNum > 1 ? msg.srcSeqNum - 1 : 0)) + msg.hopCount;

        logger->debug("Calculating hash iterations: {}", hashIterations);
        for (int i = 0; i < hashIterations; i++) {
            hashRes = sha256(hashRes);
            logger->debug("Hash iteration {}: {}", i, hashRes);
        }

        if (hashRes != this->tesla.routingTable.get(msg.recvAddr)->hash) {
            logger->error("Hash verification failed");
            logger->error("Expected: {}", this->tesla.routingTable.get(msg.recvAddr)->hash);
            logger->error("Calculated: {}", hashRes);
            return;
        }

        if (msg.srcSeqNum < this->tesla.routingTable[msg.recvAddr].seqNum) {
            logger->warn("Dropping RREP: Smaller sequence number");
            logger->warn("Received seqNum: {}, Current seqNum: {}",
                        msg.srcSeqNum, this->tesla.routingTable[msg.recvAddr].seqNum);
            return;
        }

        if (msg.destAddr == this->addr) {
            logger->info("This node is the destination for RREP");
            try {
                // Create a routing table entry with cross-swarm info if needed
                if (msg.isCrossSwarm && !msg.forwardingLeader.empty()) {
                    this->tesla.routingTable.insert(
                        msg.srcAddr,
                        ROUTING_TABLE_ENTRY(
                            msg.srcAddr,
                            msg.recvAddr,
                            msg.srcSeqNum,
                            msg.hopCount,
                            std::chrono::system_clock::now(),
                            "", true, msg.forwardingLeader, msg.tsla_key
                        )
                    );

                    this->tesla.routingTable.insert(
                        msg.recvAddr,
                        ROUTING_TABLE_ENTRY(
                            msg.recvAddr,
                            msg.recvAddr,
                            msg.srcSeqNum,
                            msg.hopCount,
                            std::chrono::system_clock::now(),
                            "", true, msg.forwardingLeader, msg.tsla_key
                        )
                    );
                } else {
                    this->tesla.routingTable.insert(
                        msg.srcAddr,
                        ROUTING_TABLE_ENTRY(
                            msg.srcAddr,
                            msg.recvAddr,
                            msg.srcSeqNum,
                            0,
                            std::chrono::system_clock::now(),
                            "", msg.tsla_key
                        )
                    );

                    this->tesla.routingTable.insert(
                        msg.recvAddr,
                        ROUTING_TABLE_ENTRY(
                            msg.recvAddr,
                            msg.recvAddr,
                            msg.srcSeqNum,
                            0,
                            std::chrono::system_clock::now(),
                            "", msg.tsla_key
                        )
                    );
                }

                {
                    std::lock_guard<std::mutex> lock(pendingRoutesMutex);
                    auto it = std::find_if(pendingRoutes.begin(), pendingRoutes.end(),
                        [&msg](const PendingRoute& route) {
                            return route.destAddr == msg.srcAddr;
                        });

                    if (it != pendingRoutes.end()) {
                        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now() -
                            (it->expirationTime - std::chrono::seconds(this->timeout_sec))).count();
                        logger->info("Route establishment to {} completed in {} ms", msg.srcAddr, duration);
                    }
                }

                logger->debug("Processing any pending routes");
                this->processPendingRoutes();

            } catch (const std::exception& e) {
                logger->error("Exception while handling destination RREP: {}", e.what());
                return;
            }
        } else {
            logger->info("Forwarding RREP to next hop");
            try {
                // Create a routing table entry with cross-swarm info if needed
                if (msg.isCrossSwarm && !msg.forwardingLeader.empty()) {
                    this->tesla.routingTable.insert(
                        msg.srcAddr,
                        ROUTING_TABLE_ENTRY(
                            msg.srcAddr,
                            msg.recvAddr,
                            msg.srcSeqNum,
                            msg.hopCount,
                            std::chrono::system_clock::now(),
                            "", true, msg.forwardingLeader, msg.tsla_key
                        )
                    );

                    this->tesla.routingTable.insert(
                        msg.recvAddr,
                        ROUTING_TABLE_ENTRY(
                            msg.recvAddr,
                            msg.recvAddr,
                            msg.srcSeqNum,
                            0,
                            std::chrono::system_clock::now(),
                            "", true, msg.forwardingLeader, msg.tsla_key
                        )
                    );
                } else if (!this->tesla.routingTable.find(msg.srcAddr)) {
                    this->tesla.routingTable.insert(
                        msg.srcAddr,
                        ROUTING_TABLE_ENTRY(
                            msg.srcAddr,
                            msg.recvAddr,
                            msg.srcSeqNum,
                            msg.hopCount,
                            std::chrono::system_clock::now(), 
                            "",
                            msg.tsla_key
                        )
                    );
                    this->tesla.routingTable.insert(
                        msg.recvAddr,
                        ROUTING_TABLE_ENTRY(
                            msg.recvAddr,
                            msg.recvAddr,
                            msg.srcSeqNum,
                            0,
                            std::chrono::system_clock::now(),
                            "", msg.tsla_key
                        )
                    );
                }

                msg.hopCount++;
                msg.hash = (msg.srcSeqNum == 1) ?
                    getHashFromChain(1, msg.hopCount) :
                    getHashFromChain(msg.srcSeqNum, msg.hopCount);
                msg.recvAddr = this->addr;

                // logger->debug("Creating RERR prime with nonce");
                // RERR rerr_prime;
                // string nonce = generate_nonce();
                // string tsla_hash = this->tesla.getCurrentHash();

                // rerr_prime.create_rerr_prime(nonce, msg.srcAddr, msg.hash);
                // msg.herr = HERR::create(rerr_prime, tsla_hash);

                // this->tesla.insert(
                //     msg.destAddr,
                //     TESLA::nonce_data{nonce, tsla_hash, msg.hash, msg.srcAddr}
                // );

                msg.tsla_key = this->tesla.getCurrentHash();
                string buf = msg.serialize();
                bytes_sent += buf.size();
                auto routeEntry = this->tesla.routingTable.get(msg.destAddr);
                if (!routeEntry) {
                    logger->error("No route entry found for destination: {}", msg.destAddr);
                    return;
                }

                // If this is a cross-swarm route and we are the leader, send to the source leader
                if (msg.isCrossSwarm && this->isLeader && !msg.forwardingLeader.empty()) {
                    logger->info("Forwarding cross-swarm RREP to source leader: {}", msg.forwardingLeader);
                    sendData(msg.forwardingLeader, buf);
                } else {
                    auto nextHop = routeEntry->intermediateAddr;
                    logger->info("Forwarding RREP to next hop: {}", nextHop);
                    sendData(nextHop, buf);
                }

            } catch (const std::exception& e) {
                logger->error("Exception while forwarding RREP: {}", e.what());
                return;
            }
        }
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);

        logger->info("RREP metrics - Processing time: {} μs, Bytes sent: {}, Source Address: {}, Sequence Number: {}",
                    duration.count(), bytes_sent, msg.srcAddr, msg.srcSeqNum);
        logger->debug("=== Finished RREP Handler ===");
    } catch (const std::exception& e) {
        logger->error("Critical error in routeReplyHandler: {}", e.what());
    }
}

void drone::handleCrossSwarmRREP(json& data) {
    try {
        RREP msg;
        msg.deserialize(data);

        logger->info("Handling cross-swarm RREP from leader {} for source {}",
                     msg.forwardingLeader, msg.srcAddr);

        // Verify the leader's signature
        // (Note: No check for the signature is made here)
        if (msg.leaderSignature.empty()) {
            logger->error("Invalid cross-swarm RREP: Missing leader signature");
            return;
        }

        // Check if the destination (original requester) is in our swarm
        bool isDestInSwarm = false;
        {
            std::lock_guard<std::mutex> lock(swarmMembersMutex);
            isDestInSwarm = (swarmMembers.find(msg.destAddr) != swarmMembers.end()) ||
                           (msg.destAddr == this->addr);
        }

        if (!isDestInSwarm) {
            logger->warn("Destination {} not in this swarm, discarding RREP", msg.destAddr);
            return;
        }

        logger->info("Destination {} found in our swarm, forwarding RREP", msg.destAddr);

        // The destination is in our swarm, create a special routing table entry for the source node
        // that points to the leader of the other swarm
        {
            std::lock_guard<std::mutex> lock(routingTableMutex);
            this->tesla.routingTable.insert(msg.srcAddr,
                ROUTING_TABLE_ENTRY(msg.srcAddr, msg.forwardingLeader, msg.srcSeqNum,
                msg.hopCount, std::chrono::system_clock::now(), "",
                true, msg.forwardingLeader, msg.tsla_key));
        }

        // If we are the destination, process the RREP
        if (msg.destAddr == this->addr) {
            logger->info("This node is the destination for cross-swarm RREP");

            // Process pending routes that may now have a valid path
            this->processPendingRoutes();
        } else {
            // Forward the RREP to the destination node in our swarm
            string serialized = data.dump();
            logger->info("Forwarding cross-swarm RREP to destination: {}", msg.destAddr);
            sendData(msg.destAddr, serialized);
        }
    } catch (const std::exception& e) {
        logger->error("Error handling cross-swarm RREP: {}", e.what());
    }
}

string drone::generate_nonce(const size_t length) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    std::vector<unsigned char> random_bytes(length);
    for (size_t i = 0; i < length; ++i) {
        random_bytes[i] = static_cast<unsigned char>(dis(gen));
    }

    std::stringstream ss;
    for (const auto &byte : random_bytes) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }

    return ss.str();
}

string drone::sha256(const string& inn){
// Computes the hash X times, returns final hash
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, inn.c_str(), inn.size());
    SHA256_Final(hash, &sha256);
    std::stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    return ss.str();
}

void drone::broadcastLeaderStatus() {
    if (!this->isLeader) {
        logger->debug("Not a leader, skipping leader broadcast");
        return;
    }

    INIT_MESSAGE leader_msg;
    leader_msg.set_leader_init(this->addr, true);

    string serialized = leader_msg.serialize();
    logger->info("Broadcasting leader status: {}", serialized);
    udpInterface.broadcast(serialized);
}

void drone::neighborDiscoveryHelper(){
    /* Function on another thread to repeatedly send authenticator and TESLA broadcasts */
    string msg;
    msg = this->tesla.init_tesla(this->addr).serialize();
    logger->info("Broadcasting TESLA Init Message: {}", msg);
    udpInterface.broadcast(msg);

    msg = INIT_MESSAGE(this->hashChainCache.front(), this->addr, true).serialize();
    logger->info("Broadcasting Authenticator Init Message: {}", msg);

    // Add leader broadcast if this node is a leader
    if (this->isLeader) {
        INIT_MESSAGE leader_msg;
        leader_msg.set_leader_init(this->addr, true);
        string leader_announcement = leader_msg.serialize();
        logger->info("Broadcasting leader announcement: {}", leader_announcement);
        udpInterface.broadcast(leader_announcement);
    }

    auto phaseStartTime = std::chrono::steady_clock::now();

    while(std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - phaseStartTime).count() < DISCOVERY_INTERVAL){
        // Modification of this loop could allow for multiple discovery phases
        sleep(5);
        {
            std::lock_guard<std::mutex> lock(this->routingTableMutex);
        }

        {
            std::lock_guard<std::mutex> lock(this->helloRecvTimerMutex);
            helloRecvTimer = std::chrono::steady_clock::now();
            udpInterface.broadcast(msg);

            // Periodically broadcast leader status during discovery phase
            if (this->isLeader) {
                INIT_MESSAGE leader_msg;
                leader_msg.set_leader_init(this->addr, true);
                udpInterface.broadcast(leader_msg.serialize());
            }
        }
    }
    this->discoveryPhaseActive.store(false);
    this->swarmPhase.store(true);
    if (this->leaderFunctionalityEnabled){
        logger->info("Discovery phase complete, entering join phase");

        // If this node is not a leader, try to join a swarm
        if (!this->isLeader && !this->hasJoinedSwarm) {
            // Start a thread to periodically try to join until successful
            threads.emplace_back([this]() {
                while (swarmPhase.load() && !this->hasJoinedSwarm) {
                    this->sendJoinRequest();
                    std::this_thread::sleep_for(std::chrono::seconds(30));
                }
            });
        }
    }
}

void drone::neighborDiscoveryFunction(){
    /* HashChain is generated where the most recent hashes are stored in the front (Eg. 0th index is the most recent hash)
        Note: Code does not have implementation if the hash chain is exhausted.
        */
    unsigned char hBuf[56];
    RAND_bytes(hBuf, sizeof(hBuf));
    std::stringstream ss;
    for (int i = 0; i < sizeof(hBuf); ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hBuf[i]);
    }
    string hash = ss.str();
    int hashIterations = this->max_seq_count * this->max_hop_count;
    for (int i = 0; i < hashIterations; ++i) {
        hash = sha256(hash);
        this->hashChainCache.push_front(hash);
    }

    auto resetTableTimer = std::chrono::steady_clock::now();
    std::thread neighborDiscoveryThread([&](){
        this->neighborDiscoveryHelper();
    });

    while (true) {
        try {
            struct sockaddr_in client_addr;
            string receivedMsg = udpInterface.receiveFrom(client_addr);

            char client_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
            int client_port = ntohs(client_addr.sin_port);

            {
                std::lock_guard<std::mutex> lock(queueMutex);
                this->messageQueue.push(receivedMsg);
                logger->debug("Received message: {}", receivedMsg);
            }
            cv.notify_one();
        } catch (const std::exception& e) {
            std::cerr << "Error in neighborDiscoveryFunction: " << e.what() << std::endl;
            break;
        }
    }
}

bool drone::requestNetworkNodes() {
    if (!this->isLeader) {
        logger->warn("Non-leader drone attempting to request network nodes");
        return false;
    }

    if (pki_client->needsCertificate()) {
        logger->warn("Cannot request network nodes - no valid certificate yet");
        return false;
    }

    try {
        // Get the GCS URL from environment or use default
        std::string gcs_host = std::getenv("GCS_IP") ? std::getenv("GCS_IP") : "gcs-service.default";

        // Prepare the request
        httplib::Client client(gcs_host, 5000);
        client.set_connection_timeout(5);
        client.set_read_timeout(5);
        client.set_write_timeout(5);

        // Get our certificate
        auto cert = pki_client->getCertificate();
        if (cert.pem.empty()) {
            throw std::runtime_error("No valid certificate available");
        }

        // Create the request body
        nlohmann::json request_body = {
            {"drone_id", this->addr},
            {"certificate_pem", cert.pem}
        };

        // Send the request
        logger->info("Leader drone requesting network nodes from GCS");
        auto res = client.Post("/get_network_nodes", request_body.dump(), "application/json");

        if (!res || res->status != 200) {
            std::string error_msg = res ?
                "Request failed: " + std::to_string(res->status) + " - " + res->body :
                "No response from server";
            throw std::runtime_error(error_msg);
        }

        // Parse the response
        auto response = nlohmann::json::parse(res->body);

        if (response["status"] != "success") {
            throw std::runtime_error("Request error: " + response["message"].get<std::string>());
        }

        // Process the nodes
        std::lock_guard<std::mutex> lock(networkNodesMutex);
        networkNodes.clear();

        auto nodes = response["nodes"];
        for (auto& [drone_id, node_data] : nodes.items()) {
            NetworkNode node;
            node.drone_id = drone_id;
            node.certificate = node_data["certificate"];
            node.manufacturer_id = node_data["manufacturer_id"];
            node.issued_at = node_data["issued_at"];
            node.valid_until = node_data["valid_until"];

            networkNodes[drone_id] = std::move(node);
        }

        logger->info("Successfully retrieved {} network nodes", networkNodes.size());
        return true;

    } catch (const std::exception& e) {
        logger->error("Failed to retrieve network nodes: {}", e.what());
        return false;
    }
}

std::vector<drone::NetworkNode> drone::getNetworkNodes() {
    std::vector<NetworkNode> result;
    std::lock_guard<std::mutex> lock(networkNodesMutex);

    result.reserve(networkNodes.size());
    for (const auto& [_, node] : networkNodes) {
        result.push_back(node);
    }

    return result;
}

bool drone::isNodeInNetwork(const std::string& droneId) {
    std::lock_guard<std::mutex> lock(networkNodesMutex);
    return networkNodes.find(droneId) != networkNodes.end();
}

void drone::requestNetworkNodesIfLeader() {
    // Only perform this check once after we've received a certificate
    static bool requested = false;

    if (!requested && isLeader && !pki_client->needsCertificate()) {
        requested = true;
        if (requestNetworkNodes()) {
            logger->info("Successfully initialized network nodes as leader");
        } else {
            logger->error("Failed to initialize network nodes as leader");

            // Optional retry mechanism
            while (!requestNetworkNodes()) {
                logger->warn("Retrying to initialize network nodes as leader...");
                std::this_thread::sleep_for(std::chrono::seconds(5));
            }
            logger->info("Successfully initialized network nodes as leader after retrying");
        }
    }
}

bool drone::isValidSwarmNode(const std::string& addr) {
    std::lock_guard<std::mutex> lock(swarmMembersMutex);
    return swarmMembers.find(addr) != swarmMembers.end() || addr == this->addr;
}

void drone::sendJoinRequest() {
    if (pki_client->needsCertificate()) {
        logger->warn("Cannot send join request - no valid certificate yet");
        return;
    }

    try {
        // Get current leader
        std::string leaderAddr;
        {
            std::lock_guard<std::mutex> lock(leaderMutex);
            if (current_leader.empty()) {
                logger->debug("No leader known, can't send join request");
                return;
            }
            leaderAddr = current_leader;
        }

        JoinRequestMessage joinReq;
        joinReq.srcAddr = this->addr;
        joinReq.timestamp = std::chrono::system_clock::now();

        logger->info("Sending join request to leader: {}", leaderAddr);
        if (sendData(leaderAddr, joinReq.serialize()) != 0) {
            logger->error("Failed to send join request to leader");
        }
    } catch (const std::exception& e) {
        logger->error("Error sending join request: {}", e.what());
    }
}

void drone::joinRequestHandler(json& data) {
    if (!this->isLeader) {
        logger->debug("Ignoring join request - not a leader");
        return;
    }

    try {
        // Check if required fields exist before deserialization
        if (!data.contains("srcAddr") || !data.contains("timestamp")) {
            logger->error("Join request missing required fields");
            return;
        }

        if (!data["srcAddr"].is_string() || !data["timestamp"].is_number_integer()) {
            logger->error("Join request contains invalid field types");
            return;
        }

        JoinRequestMessage request;
        request.deserialize(data);

        // Verify the timestamp is recent
        auto now = std::chrono::system_clock::now();
        auto time_diff = std::chrono::duration_cast<std::chrono::seconds>(
            now - request.timestamp).count();
        if (std::abs(time_diff) > 30) {
            logger->warn("Received expired join request from {}", request.srcAddr);
            return;
        }

        // Challenge the node for PKI verification
        if (!isValidatedSender(request.srcAddr)) {
            logger->debug("Initiating validation for joining node {}", request.srcAddr);
            ChallengeRequest challenge;
            challenge.type = CERTIFICATE_VALIDATION;
            challenge.challenge_type = CHALLENGE_REQUEST;
            challenge.srcAddr = this->addr;
            challenge.nonce = static_cast<uint32_t>(std::random_device{}());
            challenge.timestamp = std::chrono::system_clock::now();
            challenge.challenge_data = generateChallengeData();

            pki_client->storePendingChallenge(request.srcAddr, challenge.challenge_data);

            if (sendData(request.srcAddr, challenge.serialize()) != 0) {
                logger->error("Failed to send challenge to joining node");
                return;
            }

            // The rest of the validation will happen asynchronously through existing challenge handlers
            // After validation, the node will be in validatedNodes set
            // We'll store the join request for later response
            return;
        }

        // If already validated, add to swarm members list
        bool wasNewMember = false;
        {
            std::lock_guard<std::mutex> lock(swarmMembersMutex);
            wasNewMember = swarmMembers.insert(request.srcAddr).second;
            if (wasNewMember) {
                logger->info("Added validated node {} to swarm members", request.srcAddr);
            } else {
                logger->debug("Node {} is already a swarm member", request.srcAddr);
            }
        }

        // Schedule propagation if this is a new member
        if (wasNewMember) {
            std::thread([this, requestAddr = request.srcAddr]() {
                std::this_thread::sleep_for(std::chrono::seconds(1));
                propagateValidNodeList();
                logger->info("Propagated updated valid node list after adding node {}", requestAddr);
            }).detach();
        }

        // Send response only to this newly joined member
        JoinResponseMessage response;
        response.srcAddr = this->addr;
        response.timestamp = std::chrono::system_clock::now();

        // Compile list of valid nodes
        {
            std::lock_guard<std::mutex> lock(validationMutex);
            response.validNodeList.assign(validatedNodes.begin(), validatedNodes.end());
            response.validNodeList.push_back(this->addr);
        }

        if (sendData(request.srcAddr, response.serialize()) != 0) {
            logger->error("Failed to send join response to {}", request.srcAddr);
        } else {
            logger->info("Sent join response with {} valid nodes to {}",
                        response.validNodeList.size(), request.srcAddr);
        }

    } catch (const std::exception& e) {
        logger->error("Error processing join request: {}", e.what());
    }
}

void drone::joinResponseHandler(json& data) {
    try {
        // Check if required fields exist before deserialization
        if (!data.contains("srcAddr") || !data.contains("timestamp") || !data.contains("validNodeList")) {
            logger->error("Join response missing required fields");
            return;
        }

        if (!data["srcAddr"].is_string() || !data["timestamp"].is_number_integer() ||
            !data["validNodeList"].is_array()) {
            logger->error("Join response contains invalid field types");
            return;
        }

        JoinResponseMessage response;
        response.deserialize(data);

        // Verify the timestamp is recent
        auto now = std::chrono::system_clock::now();
        auto time_diff = std::chrono::duration_cast<std::chrono::seconds>(
            now - response.timestamp).count();
        if (std::abs(time_diff) > 30) {
            logger->warn("Received expired join response from {}", response.srcAddr);
            return;
        }

        // Validate the sender is a leader
        bool isValidLeader = false;
        {
            std::lock_guard<std::mutex> lock(leaderMutex);
            isValidLeader = (response.srcAddr == current_leader);
        }

        if (!isValidLeader) {
            logger->warn("Received join response from non-leader: {}", response.srcAddr);
            return;
        }

        {
            std::lock_guard<std::mutex> lock(validNodeListMutex);
            validNodeList = response.validNodeList;
            this->hasJoinedSwarm = true;
        }
        {
            std::lock_guard<std::mutex> lock(swarmMembersMutex);
            for (const auto& node : response.validNodeList) {
                swarmMembers.insert(node);
            }
            logger->info("Added {} nodes to swarm members set", response.validNodeList.size());
        }

        logger->info("Successfully joined swarm led by {}", response.srcAddr);
        logger->info("Received valid node list with {} nodes", response.validNodeList.size());

    } catch (const std::exception& e) {
        logger->error("Error processing join response: {}", e.what());
    }
}

void drone::leaveSwarm() {
    LeaveMessage leave_msg;
    leave_msg.srcAddr = this->addr;
    leave_msg.timestamp = std::chrono::system_clock::now();

    auto cert = pki_client->getCertificate();
    if (cert.pem.empty()) {
        logger->error("No valid certificate available for leave message");
        return;
    }
    leave_msg.certificate_pem = cert.pem;

    std::string msg_data = leave_msg.srcAddr +
        std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(
            leave_msg.timestamp.time_since_epoch()).count());

    std::vector<uint8_t> data_to_sign(msg_data.begin(), msg_data.end());
    if (!pki_client->signMessage(data_to_sign)) {
        logger->error("Failed to sign leave message");
        return;
    }
    leave_msg.signature = data_to_sign;

    logger->info("Broadcasting leave notification");
    udpInterface.broadcast(leave_msg.serialize());

    {
        std::lock_guard<std::mutex> lock(validationMutex);
        validatedNodes.clear();
    }
}

std::future<void> drone::getSignal() {
    logger->info("Future requested");
    return init_promise.get_future();
}

void drone::propagateValidNodeList() {
    if (!this->isLeader) {
        logger->warn("Non-leader drone attempting to propagate valid node list");
        return;
    }

    JoinResponseMessage response;
    response.srcAddr = this->addr;
    response.timestamp = std::chrono::system_clock::now();

    {
        std::lock_guard<std::mutex> lock(validationMutex);
        response.validNodeList.assign(validatedNodes.begin(), validatedNodes.end());
        response.validNodeList.push_back(this->addr);
    }
    std::set<std::string> currentMembers;
    {
        std::lock_guard<std::mutex> lock(swarmMembersMutex);
        currentMembers = swarmMembers;
    }
    currentMembers.erase(this->addr);

    if (currentMembers.empty()) {
        logger->debug("No swarm members to send valid node list to");
        return;
    }

    logger->info("Propagating valid node list with {} nodes to {} swarm members",
                 response.validNodeList.size(), currentMembers.size());

    // Send the list to all current swarm members
    for (const auto& member : currentMembers) {
        std::thread([this, member, response]() {
            auto responseCopy = response;
            if (sendData(member, responseCopy.serialize()) != 0) {
                logger->error("Failed to propagate valid node list to swarm member {}", member);
            }
        }).detach();
    }
}

std::vector<string> drone::getOtherLeaderAddresses() {
    std::lock_guard<std::mutex> lock(knownLeadersMutex);

    // Return a copy of the leader addresses, excluding this node if it's a leader
    std::vector<string> otherLeaders;
    otherLeaders.reserve(knownLeaders.size());

    for (const auto& leader : knownLeaders) {
        if (leader != this->addr) {
            otherLeaders.push_back(leader);
        }
    }

    return otherLeaders;
}

void drone::broadcastToOtherLeaders(const string& serializedMsg, const string& originLeader) {
    // Only leaders can broadcast to other leaders
    if (!this->isLeader) {
        logger->warn("Non-leader drone attempting to broadcast to other leaders");
        return;
    }

    // Get list of other leaders
    auto otherLeaders = getOtherLeaderAddresses();
    if (otherLeaders.empty()) {
        logger->debug("No other leaders to broadcast to");
        return;
    }

    // Track this leader as visited to prevent routing loops
    visitedLeaders.insert(this->addr);

    // Add originating leader to visited set if specified
    if (!originLeader.empty() && originLeader != this->addr) {
        visitedLeaders.insert(originLeader);
    }

    logger->info("Broadcasting to {} other leaders", otherLeaders.size());

    // Send the message to all other leaders
    for (const auto& leader : otherLeaders) {
        // Skip if this leader has already been visited
        if (visitedLeaders.find(leader) != visitedLeaders.end()) {
            logger->debug("Skipping already visited leader: {}", leader);
            continue;
        }

        // Use a separate thread for each leader to avoid blocking
        std::thread([this, leader, serializedMsg]() {
            if (sendData(leader, serializedMsg) != 0) {
                logger->error("Failed to broadcast to leader {}", leader);
            } else {
                logger->debug("Successfully broadcast to leader {}", leader);
            }
        }).detach();
    }

    // Clear visited leaders once broadcast is complete
    visitedLeaders.clear();
}

void drone::refreshCRLCache() {
    if (!this->isLeader) {
        logger->debug("CRL refresh requested for non-leader drone - skipping");
        return;
    }

    if (pki_client->needsCertificate()) {
        logger->warn("Cannot refresh CRL cache - no valid certificate yet");
        return;
    }

    // Get list of certificates we need to check
    std::vector<std::pair<std::string, std::string>> certificatesToCheck;
    {
        std::lock_guard<std::mutex> lock(networkNodesMutex);
        for (const auto& [droneId, node] : networkNodes) {
            certificatesToCheck.emplace_back(droneId, node.certificate);
        }
    }

    if (certificatesToCheck.empty()) {
        logger->debug("No certificates available to check against CRL");
        return;
    }

    logger->info("Refreshing CRL status for {} certificates", certificatesToCheck.size());

    // Check if we can use the bulk endpoint
    try {
        // Use the more efficient bulk endpoint if there are multiple certificates
        if (certificatesToCheck.size() > 1) {
            json requestBody = {
                {"certificates", json::array()}
            };

            for (const auto& [_, certificate] : certificatesToCheck) {
                requestBody["certificates"].push_back(certificate);
            }

            httplib::Client client(this->GCS_IP, 5000);
            client.set_connection_timeout(5);

            auto res = client.Post("/bulk_check_crl", requestBody.dump(), "application/json");
            if (!res) {
                logger->warn("GCS connection failed during bulk CRL refresh, allowing all connections for demo purposes");

                // For the demo, create an empty cache that marks all certificates as valid
                std::lock_guard<std::mutex> lock(crlCacheMutex);
                for (const auto& [_, certificate] : certificatesToCheck) {
                    crlCache[certificate] = false; // Not revoked
                }
                crlCacheLastRefreshed = std::chrono::steady_clock::now();
                logger->info("Created empty CRL cache with {} entries for demo", certificatesToCheck.size());
                return;
            }

            if (res->status != 200) {
                logger->warn("Bulk CRL check failed: HTTP {}, allowing all connections for demo", res->status);

                // For the demo, create an empty cache that marks all certificates as valid
                std::lock_guard<std::mutex> lock(crlCacheMutex);
                for (const auto& [_, certificate] : certificatesToCheck) {
                    crlCache[certificate] = false; // Not revoked
                }
                crlCacheLastRefreshed = std::chrono::steady_clock::now();
                logger->info("Created empty CRL cache with {} entries for demo", certificatesToCheck.size());
                return;
            }

            // Parse response
            auto response = json::parse(res->body);
            if (response["status"] != "success") {
                logger->error("Bulk CRL check error: {}", response["message"].get<std::string>());
                return;
            }

            // Update cache with results
            std::lock_guard<std::mutex> lock(crlCacheMutex);
            auto results = response["results"];
            for (const auto& [certificate, isRevoked] : results.items()) {
                crlCache[certificate] = isRevoked.get<bool>();
                if (isRevoked.get<bool>()) {
                    logger->warn("Certificate {} is revoked", certificate.substr(0, 15));
                }
            }
            crlCacheLastRefreshed = std::chrono::steady_clock::now();
            logger->info("Successfully refreshed CRL cache with {} entries via bulk API", results.size());
            return;
        }
    } catch (const std::exception& e) {
        logger->error("Error during bulk CRL refresh: {}", e.what());
        // Continue with individual requests if bulk fails
    }

    // Fallback to individual CRL checks (or if there's only one certificate)
    httplib::Client client(this->GCS_IP, 5000);
    client.set_connection_timeout(5);

    std::unordered_map<std::string, bool> newCrlCache;
    bool anySuccessful = false;

    for (const auto& [droneId, certificate] : certificatesToCheck) {
        try {
            auto res = client.Get("/check_crl/" + certificate);
            if (!res) {
                logger->warn("GCS connection failed during CRL refresh for drone {}", droneId);
                continue;
            }

            if (res->status != 200) {
                // For demo purposes, we'll treat HTTP errors as if the certificate is valid
                if (res->status == 404) {
                    logger->warn("CRL check endpoint not found for drone {}, treating as valid for demo", droneId);
                } else {
                    logger->warn("Failed CRL refresh for drone {}: HTTP {}, treating as valid for demo",
                                droneId, res->status);
                }
                newCrlCache[certificate] = false; // Not revoked
                anySuccessful = true;
                continue;
            }

            json response = json::parse(res->body);
            bool is_revoked = response.value("revoked", false);

            if (is_revoked) {
                logger->warn("Certificate for drone {} is revoked", droneId);
            }

            newCrlCache[certificate] = is_revoked;
            anySuccessful = true;

        } catch (const std::exception& e) {
            logger->error("Error refreshing CRL for drone {}: {}", droneId, e.what());
        }
    }

    // Update the cache if at least one check was successful
    if (anySuccessful) {
        std::lock_guard<std::mutex> lock(crlCacheMutex);
        // Merge new cache entries with existing ones
        for (const auto& [cert, status] : newCrlCache) {
            crlCache[cert] = status;
        }
        crlCacheLastRefreshed = std::chrono::steady_clock::now();
        logger->info("Successfully refreshed CRL cache with {} entries via individual requests", newCrlCache.size());
    } else {
        logger->warn("CRL refresh failed - no successful GCS connections. Allowing all connections for demo");

        // For demo purposes, create an empty cache that treats all certificates as valid
        std::lock_guard<std::mutex> lock(crlCacheMutex);
        for (const auto& [_, certificate] : certificatesToCheck) {
            crlCache[certificate] = false; // Not revoked
        }
        crlCacheLastRefreshed = std::chrono::steady_clock::now();
        logger->info("Created empty CRL cache with {} entries for demo", certificatesToCheck.size());
    }
}

void drone::start() {
    logger->info("Starting drone initialization");

    try {
        pki_client->waitForCertificate(running);
        logger->info("Setting promise value");
        init_promise.set_value();
        logger->info("Promise value set");

        if (this->leaderFunctionalityEnabled) {
            threads.emplace_back([this](){ requestNetworkNodesIfLeader(); });

            // If this is a leader drone, start periodic CRL cache refresh
            if (this->isLeader) {
                threads.emplace_back([this]() {
                    // Initial delay to allow certificate acquisition
                    std::this_thread::sleep_for(std::chrono::seconds(10));

                    while (running) {
                        try {
                            refreshCRLCache();
                        } catch (const std::exception& e) {
                            logger->error("Error during CRL cache refresh: {}", e.what());
                        }

                        // Sleep until next refresh
                        std::this_thread::sleep_for(crlCacheLifetime / 2);
                    }
                });
            }
        }
        threads.emplace_back([this](){ neighborDiscoveryFunction(); });
        threads.emplace_back([this](){ clientResponseThread(); });

        ipc_server = std::make_unique<IPCServer>(60137,
            [this](const std::string& msg) {
                this->handleIPCMessage(msg);
            }
        );
        ipc_server->start();
        logger->info("Entering main server loop");

        while (running) {
            try {
                int clientSock = tcpInterface.accept_connection();
                threads.emplace_back([this, clientSock](){
                    try {
                        string msg = tcpInterface.receive_data(clientSock);
                        {
                            std::lock_guard<std::mutex> lock(queueMutex);
                            logger->info("Received TCP message: {}", msg);
                            messageQueue.push(msg);
                        }
                        cv.notify_one();
                    } catch (const std::exception& e) {
                        logger->error("Client handler error: {}", e.what());
                    }
                    close(clientSock);
                });
            } catch (const std::exception& e) {
                logger->error("TCP accept error: {}", e.what());
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }


        if (ipc_server) {
            ipc_server->stop();
        }
        for (auto& thread : threads) {
            if (thread.joinable()) {
                thread.join();
            }
        }

    } catch (const std::exception& e) {
        logger->critical("Fatal error during drone startup: {}", e.what());
        running = false;
        throw;
    }
}
