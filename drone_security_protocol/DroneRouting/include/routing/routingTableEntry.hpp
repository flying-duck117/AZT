#pragma once
#include <iostream>
#include <tuple>
#include <chrono>
#include <deque>
#include "messages.hpp"

using std::string;
using std::cout;
using std::endl;

struct ROUTING_TABLE_ENTRY {
    string destAddr;
    string intermediateAddr; // srcAddr = destAddr if neighbor
    int seqNum; // Destination SeqNum
    int cost; // HopCount to reach destination
    std::chrono::system_clock::time_point ttl; // Starting Timestamp at which this entry was created
    string tsla_key;
    std::chrono::seconds tesla_disclosure_time;
    string hash; // Most recent authenticator hash
    // Cross-swarm routing fields
    bool isCrossSwarm; // Flag indicating if this is a cross-swarm route
    string targetLeader; // Leader address for the destination swarm

    ROUTING_TABLE_ENTRY(){
        this->destAddr = "ERR";
        this->intermediateAddr = "ERR";
        this->seqNum = -1;
        this->cost = -1;
        this->ttl = std::chrono::system_clock::now(); // Starting Timestamp at which this entry was created
        this->hash = "";
        this->tsla_key = "ERR";
        this->tesla_disclosure_time = std::chrono::seconds(0);
        this->isCrossSwarm = false;
        this->targetLeader = "";
    }


    ROUTING_TABLE_ENTRY(string destAddr, string intermediateAddr, int seqNum, int cost, std::chrono::system_clock::time_point ttl){
        this->destAddr = destAddr;
        this->intermediateAddr = intermediateAddr;
        this->seqNum = seqNum;
        this->cost = cost;
        this->ttl = ttl;
        this->isCrossSwarm = false;
        this->targetLeader = "";
        this->tsla_key = "ERR";
    }

    ROUTING_TABLE_ENTRY(string destAddr, string intermediateAddr, int seqNum, int cost, std::chrono::system_clock::time_point ttl, string hash){
        this->destAddr = destAddr;
        this->intermediateAddr = intermediateAddr;
        this->seqNum = seqNum;
        this->cost = cost;
        this->ttl = ttl;
        this->hash = hash;
        this->isCrossSwarm = false;
        this->targetLeader = "";
    }

    ROUTING_TABLE_ENTRY(string destAddr, string intermediateAddr, int seqNum, int cost, std::chrono::system_clock::time_point ttl, string hash, string tsla_key){
        this->destAddr = destAddr;
        this->intermediateAddr = intermediateAddr;
        this->seqNum = seqNum;
        this->cost = cost;
        this->ttl = ttl;
        this->hash = hash;
        this->tsla_key = tsla_key;
        this->isCrossSwarm = false;
        this->targetLeader = "";
    }

    // Constructor with cross-swarm parameters
    ROUTING_TABLE_ENTRY(string destAddr, string intermediateAddr, int seqNum, int cost, std::chrono::system_clock::time_point ttl, string hash, bool isCrossSwarm, string targetLeader, string tsla_key){
        this->destAddr = destAddr;
        this->intermediateAddr = intermediateAddr;
        this->seqNum = seqNum;
        this->cost = cost;
        this->ttl = ttl;
        this->hash = hash;
        this->tsla_key = tsla_key;
        this->isCrossSwarm = isCrossSwarm;
        this->targetLeader = targetLeader;
    }

    void print() const {
        auto ttl_seconds = std::chrono::duration_cast<std::chrono::seconds>(ttl.time_since_epoch()).count();
        cout << "Routing entry: " << "destAddr: " << destAddr << ", intermediateAddr: " << intermediateAddr << ", seqNum: " << seqNum << ", cost: " << cost << ", ttl: " << ttl_seconds << " seconds, tsla_key: " << tsla_key << ", tesla_disclosure_time: " << tesla_disclosure_time.count() << " seconds, hash: " << hash;

        cout << ", isCrossSwarm: " << (isCrossSwarm ? "true" : "false");
        if (isCrossSwarm) {
            cout << ", targetLeader: " << targetLeader;
        }

        cout << endl;
    }

    std::tuple<string, std::chrono::seconds> getTeslaInfo() {
        if (tsla_key.compare("ERR") == 0 || tesla_disclosure_time.count() == 0) {
            throw std::runtime_error("TESLA info not found");
        }
        return std::make_tuple(tsla_key, tesla_disclosure_time);
    }

    void setTeslaInfo(string hash, std::chrono::seconds ttl) {
        this->tsla_key = hash;
        this->tesla_disclosure_time = ttl;
    }

    void setTeslaKey(string hash) {
        this->tsla_key = hash;
    }

    std::string getTeslaKey() {
        if (tsla_key.compare("ERR") == 0) {
            throw std::runtime_error("TESLA key not found");
        }
        return this->tsla_key;
    }

    friend std::ostream& operator<<(std::ostream& os, const ROUTING_TABLE_ENTRY& entry) {
        os << "{ destAddr: " << entry.destAddr << ", intermediateAddr: " << entry.intermediateAddr
           << ", seqNum: " << entry.seqNum << ", cost: " << entry.cost
           << ", ttl: " << std::chrono::duration_cast<std::chrono::seconds>(entry.ttl.time_since_epoch()).count()
           << " seconds, hash: " << entry.hash;

        if (entry.isCrossSwarm) {
            os << ", isCrossSwarm: true, targetLeader: " << entry.targetLeader;
        }

        os << " }";
        return os;
    }
};
