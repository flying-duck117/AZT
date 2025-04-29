#ifndef HASH_TREE_HPP
#define HASH_TREE_HPP
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <vector>
#include <queue>
#include <iostream>
#include <openssl/sha.h>
#include <string>
#include <sstream>
#include <cmath>

using std::string;
using std::endl;
using std::cout;

/* Leaf Nodes are hashes of droneID. In other words, the leaf node IS NOT the droneID. */

class HashTree {
private:
    class TreeNode {  
        public:
            string hash;
            TreeNode *left;
            TreeNode *right;
            TreeNode(const string&, bool);
            ~TreeNode() {};

            string hashString(const string&);
            void setLeft(TreeNode *leftNode) { left = leftNode; }
            void setRight(TreeNode *rightNode){ right = rightNode; }
            string getHash() { return hash; }
            void updateHash(std::string hash) {this->hash = hash; }

    };
    string hashSelf(const string&);
    string hashNodes(const string&, const string&);
    string recalculate(TreeNode*, const int&, const int&, const int&, const int&, const int&, const string&);
    static string bytesToHexString(unsigned char*, int);
    TreeNode *root;
    void setRoot(TreeNode* node) {this->root = node;}

    struct CacheKey {
        std::string rootHash;
        std::string droneID;
        int hopCount;
        
        bool operator==(const CacheKey& other) const {
            return rootHash == other.rootHash && 
                   droneID == other.droneID && 
                   hopCount == other.hopCount;
        }
    };
    
    struct CacheKeyHash {
        std::size_t operator()(const CacheKey& key) const {
            return std::hash<std::string>()(key.rootHash) ^ 
                   std::hash<std::string>()(key.droneID) ^ 
                   std::hash<int>()(key.hopCount);
        }
    };
    
    struct CacheEntry {
        std::vector<std::string> treeHashes;
        std::chrono::steady_clock::time_point timestamp;
    };
    
    static std::unordered_map<CacheKey, CacheEntry, CacheKeyHash> addSelfCache;
    static std::mutex cacheMutex;
    static const size_t MAX_CACHE_SIZE = 1000;
    
    std::vector<std::string> serializeTree() const;
    void deserializeTree(const std::vector<std::string>& treeHashes);

public:
    // case1: first time init tree
    HashTree(const string& droneNum) {
        std::cout << "HashTree created" << std::endl;
        this->root = new TreeNode(droneNum, false);
    }

    // case2: along the path, we are rebuilding tree
    HashTree(std::vector<string> hashes, int hopCount, string sourceAddr);

    TreeNode* getRoot() const { 
        if (!root) throw std::runtime_error("Accessing null root node");
        return root;
    }

    void deleteTree(TreeNode *node) {
        if (!node) return;
        if (node->left) deleteTree(node->left);
        if (node->right) deleteTree(node->right);
        delete node;
    }

    ~HashTree() {
        if (root) {
            deleteTree(root);
            root = nullptr;
        }
    };

    void printTree(TreeNode* node){
        if (node->left != nullptr){
            printTree(node->left);
        }
        if (node->right != nullptr){
            printTree(node->right);
        }
        std::cout << "data: " << node->hash << std::endl;
    }

    bool verifyTree(string&);
    void addSelf(const string&, const int&);
    std::vector<string> toVector();
};

#endif