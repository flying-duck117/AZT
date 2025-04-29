#include <routing/drone.hpp>

std::string drone::TESLA::createHMAC(const std::string& key, const std::string& data) {
    unsigned char* digest;
    digest = HMAC(EVP_sha256(), key.c_str(), key.length(),
                  reinterpret_cast<const unsigned char*>(data.c_str()), data.length(), NULL, NULL);

    std::stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];

    return ss.str();
}

std::string drone::TESLA::sha256(const std::string& inn) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, inn.c_str(), inn.size());
    SHA256_Final(hash, &sha256);
    std::stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    return ss.str();
}

drone::TESLA::TESLA() {
    // hashChain = new unsigned char[numKeys][SHA256_DIGEST_LENGTH];
    generateHashChain();
    logger = createLogger("tesla");
    logger->debug("Initialized");
    // assume time synchro has happened
}

drone::TESLA::~TESLA() {}

INIT_MESSAGE drone::TESLA::init_tesla(const std::string &addr) {
        this->addr = addr;
        
        INIT_MESSAGE init_msg;
        init_msg.set_tesla_init(this->addr, this->timed_hash_chain.back().hash, 
                          std::chrono::duration_cast<std::chrono::seconds>(
                              this->timed_hash_chain.back().disclosure_time.time_since_epoch()
                          ).count());

        return init_msg;

}

void drone::TESLA::generateHashChain() {
    /* Assumptions: We are not doing any wrap arounds for now
    New key is disclosed every **disclosure_time** seconds
    numKeys  = lifetime / disclosure_time
    */
    unsigned char buffer[56];
    RAND_bytes(buffer, sizeof(buffer));
    std::stringstream ss;
    for (int i = 0; i < sizeof(buffer); ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(buffer[i]);
    }
    std::string hash = ss.str();
    
    auto now = std::chrono::system_clock::now();
    
    for (int i = 0; i < numKeys; ++i) {
        hash = sha256(hash);
        auto disclosure_time = now + this->disclosure_interval * i;
        timed_hash_chain.push_front(TimedHash{disclosure_time, hash});
    }
}

void drone::TESLA::compareHashes(const unsigned char *hash1, const unsigned char *hash2) {
    if (memcmp(hash1, hash2, SHA256_DIGEST_LENGTH) == 0) {
        logger->debug("Hashes match");
    } else {
        logger->debug("Hashes do not match");
    }
}

std::string drone::TESLA::getCurrentHash() {
    auto now = std::chrono::system_clock::now();
    for (const auto& timed_hash : this->timed_hash_chain) {
        if (now >= timed_hash.disclosure_time) {
            return timed_hash.hash;
        }
    }
    return ""; // No valid hash found
}