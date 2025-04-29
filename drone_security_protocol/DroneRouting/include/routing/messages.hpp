#ifndef MESSAGES_HPP
#define MESSAGES_HPP
#include <string>
#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <netdb.h>
#include <nlohmann/json.hpp>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <chrono>
#include <vector>
#include <algorithm>

using json = nlohmann::json;
using std::cout;
using std::endl;
using std::string;

enum MESSAGE_TYPE {
    ROUTE_REQUEST = 0,
    ROUTE_REPLY,
    ROUTE_ERROR,
    DATA,
    CERTIFICATE_VALIDATION,
    LEAVE_NOTIFICATION,
    INIT_ROUTE_DISCOVERY,
    VERIFY_ROUTE,
    HELLO, // Broadcast Msg
    INIT_LEAVE,
    EXIT,
    JOIN_REQUEST,
    JOIN_RESPONSE,

};

struct MESSAGE {
    MESSAGE_TYPE type;
    virtual string serialize() const = 0;
    virtual void deserialize(json& j) = 0;
    virtual ~MESSAGE() = default;
};

struct GCS_MESSAGE : public MESSAGE { // Repurposed to request data to be sent from current node via IPC terminal to other nodes
    std::string destAddr;

    GCS_MESSAGE() {
        this->type = DATA;
        this->destAddr = "NILL";
    }

    GCS_MESSAGE(std::string destAddr, std::string msg) {
        this->type = DATA;
        this->destAddr = destAddr;
    }

    std::string serialize() const override {
        json j = json{
            {"type", this->type},
            {"destAddr", this->destAddr},
        };
        return j.dump();
    }

    void deserialize(json& j) override {
        this->type = j["type"];
        this->destAddr = j["destAddr"];
    }
};

struct RERR : public MESSAGE {
    std::vector<string> nonce_list;
    std::vector<string> tsla_list;
    std::vector<string> dst_list;
    std::vector<string> auth_list;
    std::string retAddr; // Temp
    std::string srcAddr; // Source address of the node sending the RERR
    std::string recvAddr;

    RERR() {
        this->type = ROUTE_ERROR;
    }

    RERR(std::vector<string> nonce_list, std::vector<string> tsla_list, std::vector<string> dst_list, std::vector<string> auth_list) {
        this->type = ROUTE_ERROR;
        this->nonce_list = nonce_list;
        this->tsla_list = tsla_list;
        this->dst_list = dst_list;
        this->auth_list = auth_list;
    }

    void create_rerr(const std::vector<string>& nonce_list,
                            const std::vector<string>& tsla_list,
                            const std::vector<string>& dst_list,
                            const std::vector<string>& auth_list) {
        this->type = ROUTE_ERROR;
        this->nonce_list = nonce_list;
        this->tsla_list = tsla_list;
        this->dst_list = dst_list;
        this->auth_list = auth_list;
    }

    void create_rerr(const string& nonce, const string& tsla_nonce, const string& dst, const string& auth) {
        this->type = ROUTE_ERROR;
        this->nonce_list = {nonce};
        this->tsla_list = {tsla_nonce};
        this->dst_list = {dst};
        this->auth_list = {auth};
    }

    void addRetAddr(const string& addr){
        this->retAddr = addr;
    }

    void setSrcAddr(const string& addr){
        this->srcAddr = addr;
        this->recvAddr = addr;
    }

    void create_rerr_prime(const string& nonce, const string& dst, const string& tsla_key = "") {
        this->type = ROUTE_ERROR;
        this->nonce_list = {nonce};
        this->tsla_list = tsla_key.empty() ? std::vector<string>() : std::vector<string>{tsla_key};
        this->dst_list = {dst};
    }

    string serialize() const {
        json j = json{
            {"type", this->type},
            {"retAddr", this->retAddr},
            {"srcAddr", this->srcAddr},
            {"nonce_list", this->nonce_list},
            {"tsla_list", this->tsla_list},
            {"dst_list", this->dst_list},
            {"auth_list", this->auth_list},
            {"recvAddr", this->recvAddr}
        };
        return j.dump();
    }

    void deserialize(json& j) override {
        this->type = j["type"];
        this->nonce_list = j["nonce_list"].get<std::vector<string>>();
        this->tsla_list = j["tsla_list"].get<std::vector<string>>();
        this->dst_list = j["dst_list"].get<std::vector<string>>();
        this->auth_list = j["auth_list"].get<std::vector<string>>();
        this->retAddr = j["retAddr"];
        this->srcAddr = j.contains("srcAddr") ? j["srcAddr"].get<std::string>() : "";
        this->recvAddr = j.contains("recvAddr") ? j["recvAddr"].get<std::string>() : "";
    }
};

struct HERR {
    string hRERR;
    string mac_t;

    HERR() {}

    HERR(string hash, string mac){
        this->hRERR = hash;
        this->mac_t = mac;
    }

    static HERR create(const RERR& future_rerr, const string& tesla_key) {
        string hash = compute_hash(future_rerr);
        string mac = compute_mac(hash, tesla_key);
        return HERR(hash, mac);
    }

    bool verify(const RERR& rerr, const string& tesla_key) const {
        string computed_hash = compute_hash(rerr);
        string computed_mac = compute_mac(computed_hash, tesla_key);

        bool hash_match = (computed_hash == hRERR);
        bool mac_match = (computed_mac == mac_t);
        std::cout << "  Hash match: " << (hash_match ? "YES" : "NO") << std::endl;
        std::cout << "  MAC match: " << (mac_match ? "YES" : "NO") << std::endl;

        return hash_match && mac_match;
    }

    json to_json() const { // FOR DEBUG PURPOSES ONLY
        return json{
            {"hRERR", hRERR},
            {"mac_t", mac_t}
        };
    }

    static HERR from_json(const json& j) { // FOR DEBUG PURPOSES ONLY
        return HERR(j["hRERR"], j["mac_t"]);
    }

    private:
    static string compute_hash(const RERR& rerr) {
        // Create a normalized JSON representation for consistent hashing
        // This is important because the order of fields in JSON objects can vary
        json j = json{
            {"nonce_list", rerr.nonce_list},
            {"tsla_list", rerr.tsla_list},
            {"dst_list", rerr.dst_list},
            {"auth_list", rerr.auth_list}
        };

        // Sort keys to ensure consistent serialization
        string normalized_rerr = j.dump();

        // Hash the normalized representation
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, normalized_rerr.c_str(), normalized_rerr.size());
        SHA256_Final(hash, &sha256);
        std::stringstream ss;
        for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
        }
        return ss.str();
    }

    static string compute_mac(const std::string& data, const std::string& key) {
        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned int digest_len;

        HMAC(EVP_sha256(),
            key.c_str(), key.length(),
            reinterpret_cast<const unsigned char*>(data.c_str()), data.length(),
            digest, &digest_len);

        std::stringstream ss;
        for(unsigned int i = 0; i < digest_len; i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
        }
        return ss.str();
    }

    friend std::ostream& operator<<(std::ostream& os, const HERR& herr) {
        os << "HERR{hRERR: " << herr.hRERR << ", mac_t: " << herr.mac_t << "}";
        return os;
    }
};

struct RREQ : public MESSAGE {
    string srcAddr;
    string recvAddr; // temp field used to store next hop addr, since we are using services, cannnot directly extract last recieved ip
    string destAddr;
    unsigned long srcSeqNum;
    unsigned long destSeqNum;
    string hash;
    string rootHash;
    std::vector<string> hashTree; // can optimize later to use memory more efficiently
    unsigned long hopCount;
    std::string tsla_key;
    int ttl; // Max number of hops allowed for RREQ to propagate through network
    bool isCrossSwarm; // Flag to indicate cross-swarm communication
    string forwardingLeader; // Leader address that is forwarding this request
    string leaderSignature; // Cryptographic signature for leader verification

    RREQ() {
        this->type = ROUTE_REQUEST;
        this->srcSeqNum = 0;
        this->destSeqNum = 0;
        this->hash = "";
        this->hopCount = 0;
        this->rootHash = "";
        this->ttl = 0;
        this->isCrossSwarm = false;
        this->forwardingLeader = "";
        this->leaderSignature = "";
    }

    RREQ(string srcAddr, string interAddr, string destAddr, unsigned long srcSeqNum, unsigned long destSeqNum,
         string hash, unsigned long hopCount, std::vector<string> hashTree, int ttl, string rootHash,
         bool isCrossSwarm = false, string forwardingLeader = "", string leaderSignature = "", string tsla_key="") {
        this->type = ROUTE_REQUEST;
        this->srcAddr = srcAddr; // address of origin
        this->recvAddr = interAddr;
        this->destAddr = destAddr;
        this->srcSeqNum = srcSeqNum;
        this->destSeqNum = destSeqNum;
        this->hash = hash;
        this->hopCount = hopCount;
        this->tsla_key = tsla_key;
        this->hashTree = hashTree;
        this->ttl = ttl;
        this->rootHash = rootHash;
        this->isCrossSwarm = isCrossSwarm;
        this->forwardingLeader = forwardingLeader;
        this->leaderSignature = leaderSignature;
    }

    string serialize() const override {
        json j = json{
            {"type", this->type},
            {"srcAddr", this->srcAddr},
            {"destAddr", this->destAddr},
            {"recvAddr", this->recvAddr},
            {"srcSeqNum", this->srcSeqNum},
            {"destSeqNum", this->destSeqNum},
            {"hash", this->hash},
            {"hopCount", this->hopCount},
            {"hashTree", this->hashTree},
            {"ttl", this->ttl},
            {"rootHash", this->rootHash},
            {"tsla_key", this->tsla_key},
            {"isCrossSwarm", this->isCrossSwarm},
            {"forwardingLeader", this->forwardingLeader},
            {"leaderSignature", this->leaderSignature}
        };

        return j.dump();
    }

    void deserialize(json& j) override {
        this->type = j["type"];
        this->srcAddr = j["srcAddr"];
        this->destAddr = j["destAddr"];
        this->recvAddr = j["recvAddr"];
        this->srcSeqNum = j["srcSeqNum"];
        this->destSeqNum = j["destSeqNum"];
        this->hash = j["hash"];
        this->hopCount = j["hopCount"];
        this->hashTree = j["hashTree"].get<std::vector<string>>();
        this->ttl = j["ttl"];
        this->rootHash = j["rootHash"];
        this->tsla_key = j["tsla_key"];

        // Cross-swarm fields (with backward compatibility for older messages)
        this->isCrossSwarm = j.contains("isCrossSwarm") ? j["isCrossSwarm"].get<bool>() : false;
        this->forwardingLeader = j.contains("forwardingLeader") ? j["forwardingLeader"].get<std::string>() : "";
        this->leaderSignature = j.contains("leaderSignature") ? j["leaderSignature"].get<std::string>() : "";
    }
};

struct RREP : public MESSAGE {
    string srcAddr;
    string recvAddr; // same temp field as RREQ
    string destAddr;
    unsigned long srcSeqNum;
    unsigned long destSeqNum;
    string hash;
    unsigned long hopCount;
    string tsla_key;
    int ttl;
    bool isCrossSwarm; // Flag to indicate cross-swarm communication
    string forwardingLeader; // Leader address that is forwarding this reply
    string leaderSignature; // Cryptographic signature for leader verification

    RREP() {
        this->type = ROUTE_REPLY;
        this->srcSeqNum = 0;
        this->destSeqNum = 0;
        this->hash = "";
        this->hopCount = 0;
        this->ttl = 0;
        this->isCrossSwarm = false;
        this->forwardingLeader = "";
        this->leaderSignature = "";
    }

    RREP(string srcAddr, string destAddr, unsigned long srcSeqNum, unsigned long destSeqNum, string hash,
         unsigned long hopCount, int ttl, bool isCrossSwarm = false,
         string forwardingLeader = "", string leaderSignature = "", string tsla_key="") {
        this->type = ROUTE_REPLY;
        this->srcAddr = srcAddr;
        this->destAddr = destAddr;
        this->srcSeqNum = srcSeqNum;
        this->destSeqNum = destSeqNum;
        this->hash = hash;
        this->hopCount = hopCount;
        this->tsla_key = tsla_key;
        this->ttl = ttl;
        this->isCrossSwarm = isCrossSwarm;
        this->forwardingLeader = forwardingLeader;
        this->leaderSignature = leaderSignature;
    }

    string serialize() const override {
        json j = json{
            {"type", this->type},
            {"srcAddr", this->srcAddr},
            {"destAddr", this->destAddr},
            {"recvAddr", this->recvAddr},
            {"srcSeqNum", this->srcSeqNum},
            {"destSeqNum", this->destSeqNum},
            {"hash", this->hash},
            {"hopCount", this->hopCount},
            {"tsla_key", this->tsla_key},
            {"ttl", this->ttl},
            {"isCrossSwarm", this->isCrossSwarm},
            {"forwardingLeader", this->forwardingLeader},
            {"leaderSignature", this->leaderSignature}
        };
        return j.dump();
    }

    void deserialize(json& j) override {
        this->type = j["type"];
        this->srcAddr = j["srcAddr"];
        this->destAddr = j["destAddr"];
        this->recvAddr = j["recvAddr"];
        this->srcSeqNum = j["srcSeqNum"];
        this->destSeqNum = j["destSeqNum"];
        this->hash = j["hash"];
        this->hopCount = j["hopCount"];
        this->tsla_key = j["tsla_key"];
        this->ttl = j["ttl"];

        // Cross-swarm fields (with backward compatibility for older messages)
        this->isCrossSwarm = j.contains("isCrossSwarm") ? j["isCrossSwarm"].get<bool>() : false;
        this->forwardingLeader = j.contains("forwardingLeader") ? j["forwardingLeader"].get<std::string>() : "";
        this->leaderSignature = j.contains("leaderSignature") ? j["leaderSignature"].get<std::string>() : "";
    }

};

struct INIT_MESSAGE : public MESSAGE {
    enum INIT_MODE {
        AUTH,
        TESLA,
        LEADER
    };
    INIT_MODE mode;
    string hash;
    string srcAddr;
    int disclosure_time;
    bool is_leader;

    INIT_MESSAGE() {
        this->type = HELLO;
        hash = "";
        srcAddr = "";
    }

    INIT_MESSAGE(string hash, string addr, bool mode) {
        this->type = HELLO;
        this->hash = hash;
        this->srcAddr = addr;
        this->mode = mode ? AUTH :TESLA;
    }

    void set_tesla_init(string srcAddr, string hash, int disclosure_time) {
        this->srcAddr = srcAddr;
        this->hash = hash;
        this->disclosure_time = disclosure_time;
        this->mode = TESLA;
    }

    void set_leader_init(string srcAddr, bool leader_status) {
        this->srcAddr = srcAddr;
        this->is_leader = leader_status;
        this->mode = LEADER;
    }

    string serialize() const override {
        json j = json{
            {"type", this->type},
            {"hash", this->hash},
            {"srcAddr", this->srcAddr},
            {"mode", this->mode},
            {"is_leader", this->is_leader}
        };

        if (this->mode == TESLA) {
            j["disclosure_time"] = this->disclosure_time;
        }

        return j.dump();
    }

    void deserialize(json& j) override {
        this->type = j["type"];
        this->hash = j["hash"];
        this->srcAddr = j["srcAddr"];
        this->mode = j["mode"];

        // Add deserialization for is_leader field
        if (j.contains("is_leader")) {
            this->is_leader = j["is_leader"];
        } else {
            this->is_leader = false;
        }

        if (this->mode == TESLA) {
            this->disclosure_time = j["disclosure_time"];
        }
    }
};

struct DATA_MESSAGE : public MESSAGE {
    bool isBroadcast;
    string destAddr;
    string srcAddr;
    string data;
    bool isCrossSwarm; // Flag to indicate cross-swarm communication
    string forwardingLeader; // Leader address that is forwarding this message
    string leaderSignature; // Cryptographic signature for leader verification

    DATA_MESSAGE() {
        isBroadcast = false;
        this->type = DATA;
        this->destAddr = "";
        this->data = "";
        this->isCrossSwarm = false;
        this->forwardingLeader = "";
        this->leaderSignature = "";
    }

    DATA_MESSAGE(string destAddr, string srcAddr, string data, bool isBroadcast = false,
                bool isCrossSwarm = false, string forwardingLeader = "", string leaderSignature = "") {
        this->isBroadcast = isBroadcast;
        this->type = DATA;
        this->srcAddr = srcAddr;
        this->destAddr = destAddr;
        this->data = data;
        this->isCrossSwarm = isCrossSwarm;
        this->forwardingLeader = forwardingLeader;
        this->leaderSignature = leaderSignature;
    }

    string serialize() const override {
        json j = json{
            {"type", this->type},
            {"isBroadcast", this->isBroadcast},
            {"srcAddr", this->srcAddr},
            {"destAddr", this->destAddr},
            {"data", this->data},
            {"isCrossSwarm", this->isCrossSwarm},
            {"forwardingLeader", this->forwardingLeader},
            {"leaderSignature", this->leaderSignature}
        };
        return j.dump();
    }

    void deserialize(json& j) override {
        this->type = j["type"];
        this->isBroadcast = j["isBroadcast"];
        this->destAddr = j["destAddr"];
        this->srcAddr = j["srcAddr"];
        this->data = j["data"];

        // Cross-swarm fields (with backward compatibility for older messages)
        this->isCrossSwarm = j.contains("isCrossSwarm") ? j["isCrossSwarm"].get<bool>() : false;
        this->forwardingLeader = j.contains("forwardingLeader") ? j["forwardingLeader"].get<std::string>() : "";
        this->leaderSignature = j.contains("leaderSignature") ? j["leaderSignature"].get<std::string>() : "";
    }
};

enum CHALLENGE_TYPE {
    CHALLENGE_REQUEST = 0,
    CHALLENGE_RESPONSE
};
struct ChallengeMessage : public MESSAGE {
    CHALLENGE_TYPE challenge_type;
    std::string srcAddr;
    uint32_t nonce;
    std::chrono::system_clock::time_point timestamp;

    virtual std::string serialize() const override {
        json j;
        j["type"] = type;
        j["challenge_type"] = challenge_type;
        j["srcAddr"] = srcAddr;
        j["nonce"] = nonce;
        j["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
            timestamp.time_since_epoch()).count();
        return j.dump();
    }

    virtual void deserialize(json& j) override {
        type = j["type"];
        challenge_type = j["challenge_type"];
        srcAddr = j["srcAddr"];
        nonce = j["nonce"];
        timestamp = std::chrono::system_clock::time_point(
            std::chrono::milliseconds(j["timestamp"].get<int64_t>()));
    }
};

struct ChallengeResponse : public ChallengeMessage {
    std::string certificate_pem;
    std::vector<uint8_t> signature;
    std::vector<uint8_t> challenge_data;

    ChallengeResponse() {
        type = CERTIFICATE_VALIDATION;
        challenge_type = CHALLENGE_RESPONSE;
    }

    std::string serialize() const override {
        json j = json::parse(ChallengeMessage::serialize());
        j["certificate_pem"] = certificate_pem;

        auto encode_base64 = [](const std::vector<uint8_t>& data) -> std::string {
            if (data.empty()) {
                return "";
            }

            BIO* bio = BIO_new(BIO_s_mem());
            BIO* b64 = BIO_new(BIO_f_base64());
            BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
            bio = BIO_push(b64, bio);

            BIO_write(bio, data.data(), data.size());
            BIO_flush(bio);

            char* encoded_data;
            long data_len = BIO_get_mem_data(bio, &encoded_data);
            std::string result(encoded_data, data_len);

            BIO_free_all(bio);
            return result;
        };

        j["signature"] = encode_base64(signature);
        j["challenge_data"] = encode_base64(challenge_data);

        return j.dump();
    }

    void deserialize(json& j) override {
        ChallengeMessage::deserialize(j);
        certificate_pem = j["certificate_pem"].get<std::string>();

        auto decode_base64 = [](const std::string& encoded) -> std::vector<uint8_t> {
            if (encoded.empty()) {
                return std::vector<uint8_t>();
            }

            try {
                std::string cleaned_input = encoded;
                cleaned_input.erase(std::remove_if(cleaned_input.begin(), cleaned_input.end(),
                    [](char c) { return std::isspace(c) || c == '\0'; }), cleaned_input.end());
                switch (cleaned_input.length() % 4) {
                    case 2: cleaned_input += "=="; break;
                    case 3: cleaned_input += "="; break;
                }

                BIO* bio = BIO_new_mem_buf(cleaned_input.data(), cleaned_input.size());
                if (!bio) {
                    throw std::runtime_error("Failed to create memory BIO");
                }

                BIO* b64 = BIO_new(BIO_f_base64());
                if (!b64) {
                    BIO_free(bio);
                    throw std::runtime_error("Failed to create base64 BIO");
                }

                BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
                bio = BIO_push(b64, bio);

                std::vector<uint8_t> decoded((cleaned_input.size() * 3) / 4);
                if (decoded.empty()) {
                    decoded.resize(1); // Ensure at least one byte for small inputs
                }

                int decoded_length = BIO_read(bio, decoded.data(), decoded.size());
                BIO_free_all(bio);

                if (decoded_length <= 0) {
                    if (cleaned_input.empty()) {
                        return std::vector<uint8_t>();
                    }
                    throw std::runtime_error("BIO_read failed with input: " + cleaned_input);
                }

                decoded.resize(decoded_length);
                return decoded;

            } catch (const std::exception& e) {
                throw std::runtime_error(std::string("Base64 decode error: ") + e.what());
            }
        };

        try {
            const auto& sig_str = j["signature"].get<std::string>();
            const auto& chal_str = j["challenge_data"].get<std::string>();

            signature = decode_base64(sig_str);
            challenge_data = decode_base64(chal_str);

        } catch (const json::exception& e) {
            throw std::runtime_error(std::string("JSON parsing error: ") + e.what());
        } catch (const std::exception& e) {
            throw std::runtime_error(std::string("Data decode error: ") + e.what());
        }
    }
};

struct ChallengeRequest : public ChallengeMessage {
    std::vector<uint8_t> challenge_data;

    ChallengeRequest() {
        type = CERTIFICATE_VALIDATION;
        challenge_type = CHALLENGE_REQUEST;
    }

    std::string serialize() const override {
        json j = json::parse(ChallengeMessage::serialize());

        if (!challenge_data.empty()) {
            BIO* bio = BIO_new(BIO_s_mem());
            BIO* b64 = BIO_new(BIO_f_base64());
            BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
            bio = BIO_push(b64, bio);

            BIO_write(bio, challenge_data.data(), challenge_data.size());
            BIO_flush(bio);

            char* encoded_data;
            long data_len = BIO_get_mem_data(bio, &encoded_data);
            std::string encoded_challenge(encoded_data, data_len);

            BIO_free_all(bio);
            j["challenge_data"] = encoded_challenge;
        } else {
            j["challenge_data"] = "";
        }

        return j.dump();
    }

    void deserialize(json& j) override {
        ChallengeMessage::deserialize(j);

        std::string encoded_challenge = j["challenge_data"].get<std::string>();
        if (encoded_challenge.empty()) {
            challenge_data.clear();
            return;
        }

        encoded_challenge.erase(
            std::remove_if(encoded_challenge.begin(), encoded_challenge.end(),
                [](char c) { return std::isspace(c) || c == '\0'; }),
            encoded_challenge.end()
        );

        switch (encoded_challenge.length() % 4) {
            case 2: encoded_challenge += "=="; break;
            case 3: encoded_challenge += "="; break;
        }

        BIO* bio = BIO_new_mem_buf(encoded_challenge.data(), encoded_challenge.size());
        BIO* b64 = BIO_new(BIO_f_base64());
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        bio = BIO_push(b64, bio);

        std::vector<uint8_t> decoded_data((encoded_challenge.size() * 3) / 4);
        if (decoded_data.empty()) {
            decoded_data.resize(1);
        }

        int decoded_length = BIO_read(bio, decoded_data.data(), decoded_data.size());
        BIO_free_all(bio);

        if (decoded_length < 0) {
            throw std::runtime_error("Failed to decode challenge data");
        }

        decoded_data.resize(decoded_length);
        challenge_data = std::move(decoded_data);
    }
};

struct LeaveMessage : public MESSAGE {
    std::string srcAddr;
    std::chrono::system_clock::time_point timestamp;
    std::vector<uint8_t> signature;
    std::string certificate_pem;

    LeaveMessage() {
        this->type = LEAVE_NOTIFICATION;
    }

    string serialize() const override {
        json j;
        j["type"] = type;
        j["srcAddr"] = srcAddr;
        j["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
            timestamp.time_since_epoch()).count();

        if (!signature.empty()) {
            BIO* bio = BIO_new(BIO_s_mem());
            BIO* b64 = BIO_new(BIO_f_base64());
            BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
            bio = BIO_push(b64, bio);

            BIO_write(bio, signature.data(), signature.size());
            BIO_flush(bio);

            char* encoded_data;
            long data_len = BIO_get_mem_data(bio, &encoded_data);
            std::string encoded_sig(encoded_data, data_len);

            BIO_free_all(bio);
            j["signature"] = encoded_sig;
        } else {
            j["signature"] = "";
        }

        j["certificate_pem"] = certificate_pem;

        return j.dump();
    }

    void deserialize(json& j) override {
        type = j["type"];
        srcAddr = j["srcAddr"];
        timestamp = std::chrono::system_clock::time_point(
            std::chrono::milliseconds(j["timestamp"].get<int64_t>()));
        certificate_pem = j["certificate_pem"];

        std::string encoded_sig = j["signature"].get<std::string>();
        if (!encoded_sig.empty()) {
            encoded_sig.erase(std::remove_if(encoded_sig.begin(), encoded_sig.end(),
                [](char c) { return std::isspace(c) || c == '\0'; }), encoded_sig.end());

            switch (encoded_sig.length() % 4) {
                case 2: encoded_sig += "=="; break;
                case 3: encoded_sig += "="; break;
            }

            BIO* bio = BIO_new_mem_buf(encoded_sig.data(), encoded_sig.size());
            BIO* b64 = BIO_new(BIO_f_base64());
            BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
            bio = BIO_push(b64, bio);

            std::vector<uint8_t> decoded((encoded_sig.size() * 3) / 4);
            if (decoded.empty()) {
                decoded.resize(1);
            }

            int decoded_length = BIO_read(bio, decoded.data(), decoded.size());
            BIO_free_all(bio);

            if (decoded_length > 0) {
                decoded.resize(decoded_length);
                signature = std::move(decoded);
            }
        }
    }
};

struct JoinRequestMessage : public MESSAGE {
    std::string srcAddr;
    std::chrono::system_clock::time_point timestamp;

    JoinRequestMessage() {
        this->type = JOIN_REQUEST;
    }

    string serialize() const override {
        json j = json{
            {"type", this->type},
            {"srcAddr", this->srcAddr},
            {"timestamp", std::chrono::duration_cast<std::chrono::milliseconds>(
                timestamp.time_since_epoch()).count()}
        };
        return j.dump();
    }

    void deserialize(json& j) override {
        this->type = j["type"];
        this->srcAddr = j["srcAddr"];
        this->timestamp = std::chrono::system_clock::time_point(
            std::chrono::milliseconds(j["timestamp"].get<int64_t>()));
    }
};

struct JoinResponseMessage : public MESSAGE {
    std::string srcAddr;
    std::vector<std::string> validNodeList;
    std::chrono::system_clock::time_point timestamp;

    JoinResponseMessage() {
        this->type = JOIN_RESPONSE;
    }

    string serialize() const override {
        json j = json{
            {"type", this->type},
            {"srcAddr", this->srcAddr},
            {"validNodeList", this->validNodeList},
            {"timestamp", std::chrono::duration_cast<std::chrono::milliseconds>(
                timestamp.time_since_epoch()).count()}
        };
        return j.dump();
    }

    void deserialize(json& j) override {
        this->type = j["type"];
        this->srcAddr = j["srcAddr"];
        this->validNodeList = j["validNodeList"].get<std::vector<std::string>>();
        this->timestamp = std::chrono::system_clock::time_point(
            std::chrono::milliseconds(j["timestamp"].get<int64_t>()));
    }
};

#endif
