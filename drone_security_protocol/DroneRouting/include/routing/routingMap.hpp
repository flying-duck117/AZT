#include <iostream>
#include <unordered_map>
#include <chrono>
#include <optional>
#include <string>
#include "routingTableEntry.hpp"

#ifndef ROUTING_MAP_HPP
#define ROUTING_MAP_HPP

using namespace std::chrono;

template <typename Key, typename Value>
class RoutingMap {
public:
    Value& operator[](const Key& key) {
        return map[key];
    }

    bool find(const Key& key) {
        /* Returns true if key is found. Else returns false. */
        return map.find(key) != map.end();
    }

    void cleanup() {
        auto now = std::chrono::system_clock::now();
        for (auto it = map.begin(); it != map.end(); ) {
            if (std::chrono::duration_cast<std::chrono::seconds>(now - it->second.ttl) > seconds(90)) {
                it = map.erase(it);
            } else {
                ++it;
            }
        }
    }

    Value* get(const Key& key) {
        /* Returns pointer to value if found. Else returns nullptr. */
        auto it = map.find(key);
        if (it == map.end()) {
            return nullptr;
        }
        return &(it->second);
    }

    void print() const {
        for (const auto& pair : map) {
            std::cout << "Key: " << pair.first << ", Value: ";
            pair.second.print();
        }
    }

    void insert(const Key& key, const Value& value, std::optional<HERR> herr_val = std::nullopt) {
        auto it = map.find(key);
        
        if (it == map.end()) {
            map[key] = value;
        } else {
            it->second.destAddr = value.destAddr;
            it->second.intermediateAddr = value.intermediateAddr;
            it->second.seqNum = value.seqNum;
            it->second.cost = value.cost;
            it->second.tsla_key = value.tsla_key;
            if (!value.hash.empty()) { 
                it->second.hash = value.hash;
            }
        }
    }

    void remove(const Key& key) {
        map.erase(key);
    }
 

private:
    std::unordered_map<Key, Value> map;
};

#endif
