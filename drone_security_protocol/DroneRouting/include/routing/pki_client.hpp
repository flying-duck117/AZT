#pragma once
#include <string_view>
#include <memory>
#include <vector>
#include <iostream>
#include "httplib.h"
#include <atomic>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <nlohmann/json.hpp>
#include <unordered_map>
#include "messages.hpp"

using json = nlohmann::json;

class PKIClient {
public:
    struct CertificateData {
        std::string pem;
        std::string serialNumber;
        std::string caPublicKey;
    };

    using CertStatusCallback = std::function<void(bool)>;

    PKIClient(std::string_view serial,
              std::string_view eeprom_id,
              CertStatusCallback status_callback = nullptr);

    PKIClient(const PKIClient&) = delete;
    PKIClient& operator=(const PKIClient&) = delete;
    ~PKIClient() = default;

    [[nodiscard]] bool needsCertificate() const noexcept {
        return !has_valid_cert_.load(std::memory_order_acquire);
    }

    [[nodiscard]] bool validatePeer(json& msg);
    [[nodiscard]] bool signMessage(std::vector<uint8_t>& msg_data);
    [[nodiscard]] bool verifyMessage(const std::vector<uint8_t>& msg_data,
                                   const std::vector<uint8_t>& signature);

    void waitForCertificate(std::atomic<bool>& running);

    CertificateData getCertificate() const noexcept { return m_certificate; }
    void storePendingChallenge(const std::string& serial, const std::vector<uint8_t>& challenge);

private:
    CertificateData m_certificate;
    [[nodiscard]] bool requestCertificate();

    std::string serial_;
    std::string eeprom_id_;
    std::atomic<bool> has_valid_cert_;
    std::vector<uint8_t> cert_data_;
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key_;
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> md_ctx_;
    CertStatusCallback status_callback_;

    std::unordered_map<std::string, std::vector<uint8_t>> pending_challenges;
    std::mutex challenge_mutex;

    std::string GCS_IP;
};
