#include <routing/pki_client.hpp>

PKIClient::PKIClient(std::string_view serial,
                    std::string_view eeprom_id,
                    CertStatusCallback status_callback)
    : serial_(serial)
    , eeprom_id_(eeprom_id)
    , has_valid_cert_(false)
    , key_(EVP_PKEY_new(), EVP_PKEY_free)
    , md_ctx_(EVP_MD_CTX_new(), EVP_MD_CTX_free)
    , status_callback_(std::move(status_callback)) {

    // Check and set GCS_IP
    const char* gcs_ip_env = std::getenv("GCS_IP");
    if (!gcs_ip_env) {
        std::cerr << "Error: GCS_IP environment variable not set" << std::endl;
        throw std::runtime_error("GCS_IP environment variable not set");
    }
    GCS_IP = gcs_ip_env;

    // Generate EC key and convert to EVP_PKEY
    auto ec_key = std::unique_ptr<EC_KEY, decltype(&EC_KEY_free)>(
        EC_KEY_new_by_curve_name(NID_X9_62_prime256v1), EC_KEY_free);

    if (!ec_key || !EC_KEY_generate_key(ec_key.get()) ||
        !EVP_PKEY_assign_EC_KEY(key_.get(), ec_key.release())) {
        throw std::runtime_error("Key generation failed");
    }

    requestCertificate();
}

bool PKIClient::verifyMessage(const std::vector<uint8_t>& msg_data,
                            const std::vector<uint8_t>& signature) {
    if (!has_valid_cert_.load(std::memory_order_acquire)) return false;

    try {
        return EVP_DigestVerifyInit(md_ctx_.get(), nullptr, EVP_sha256(), nullptr, key_.get()) &&
               EVP_DigestVerifyUpdate(md_ctx_.get(), msg_data.data(), msg_data.size()) &&
               EVP_DigestVerifyFinal(md_ctx_.get(), signature.data(), signature.size()) == 1;
    } catch (...) {
        return false;
    }
}

bool PKIClient::requestCertificate() {
    try {
        // Create and configure CSR
        auto csr = std::unique_ptr<X509_REQ, decltype(&X509_REQ_free)>(X509_REQ_new(), X509_REQ_free);
        if (!csr) {
            throw std::runtime_error("Failed to create CSR object");
        }

        auto name = std::unique_ptr<X509_NAME, decltype(&X509_NAME_free)>(X509_NAME_new(), X509_NAME_free);
        if (!name) {
            throw std::runtime_error("Failed to create X509_NAME object");
        }

        if (!X509_NAME_add_entry_by_txt(name.get(), "CN", MBSTRING_ASC,
                reinterpret_cast<const unsigned char*>(serial_.c_str()), -1, -1, 0)) {
            throw std::runtime_error("Failed to set CSR subject name");
        }

        if (!X509_REQ_set_subject_name(csr.get(), name.get())) {
            throw std::runtime_error("Failed to set CSR subject");
        }

        if (!X509_REQ_set_pubkey(csr.get(), key_.get())) {
            throw std::runtime_error("Failed to set CSR public key");
        }

        if (!X509_REQ_sign(csr.get(), key_.get(), EVP_sha256())) {
            throw std::runtime_error("Failed to sign CSR");
        }

        // Convert CSR to PEM
        auto bio = std::unique_ptr<BIO, decltype(&BIO_free)>(BIO_new(BIO_s_mem()), BIO_free);
        if (!bio) {
            throw std::runtime_error("Failed to create BIO object");
        }

        if (!PEM_write_bio_X509_REQ(bio.get(), csr.get())) {
            throw std::runtime_error("Failed to write CSR to PEM format");
        }

        char* pem_data;
        long pem_len = BIO_get_mem_data(bio.get(), &pem_data);
        if (pem_len <= 0 || !pem_data) {
            throw std::runtime_error("Failed to get PEM data from BIO");
        }

        // Ensure the PEM data is properly terminated
        std::string csr_pem(pem_data, pem_len);

        // Log request details (excluding sensitive data)
        std::cout << "Requesting certificate from GCS at " << this->GCS_IP << std::endl;
        std::cout << "Using serial: " << serial_ << ", eeprom_id: " << eeprom_id_ << std::endl;

        // Send request to GCS
        httplib::Client client(this->GCS_IP, 5000);
        client.set_connection_timeout(5);
        client.set_read_timeout(5);
        client.set_write_timeout(5);

        // Create the JSON payload
        auto payload = nlohmann::json({
            {"serial_number", serial_},
            {"eeprom_id", eeprom_id_},
            {"csr", csr_pem}
        }).dump();

        auto res = client.Post("/request_certificate", payload, "application/json");

        if (!res) {
            throw std::runtime_error("No response from GCS server. Check network connectivity and server status.");
        }

        if (res->status != 200) {
            // Try to parse the error message from the response if available
            std::string error_msg = "Request failed with status code: " + std::to_string(res->status);
            try {
                auto error_json = nlohmann::json::parse(res->body);
                if (error_json.contains("message") && error_json["message"].is_string()) {
                    error_msg += " - " + error_json["message"].get<std::string>();
                }
            } catch (...) {
                // If we can't parse the error JSON, just use the body as is
                if (!res->body.empty()) {
                    error_msg += " - Response: " + res->body;
                }
            }
            throw std::runtime_error(error_msg);
        }

        auto response = nlohmann::json::parse(res->body);
        if (!response["certificate"]["certificate_data"]["pem"].is_string()) {
            throw std::runtime_error("Invalid certificate format in response");
        }

        // Store both the raw data and structured certificate
        std::string cert_str = response["certificate"]["certificate_data"]["pem"].get<std::string>();
        cert_data_.assign(cert_str.begin(), cert_str.end());

        // Store the certificate in m_certificate
        m_certificate = {
            .pem = cert_str,
            .serialNumber = response["certificate"]["certificate_data"].value("serial_number", ""),
            .caPublicKey = response["certificate"]["certificate_data"]["ca_public_key"].get<std::string>()
        };

        std::cout << "Successfully obtained certificate from GCS" << std::endl;
        has_valid_cert_.store(true, std::memory_order_release);
        if (status_callback_) status_callback_(true);
        return true;

    } catch (const std::exception& e) {
        std::cerr << "Certificate request failed: " << e.what() << std::endl;
        if (status_callback_) status_callback_(false);
        return false;
    }
}

void PKIClient::storePendingChallenge(const std::string& serial,
                                    const std::vector<uint8_t>& challenge) {
    std::lock_guard<std::mutex> lock(challenge_mutex);
    pending_challenges[serial] = challenge;

    // Schedule cleanup after timeout
    std::thread([this, serial]() {
        std::this_thread::sleep_for(std::chrono::seconds(30));
        std::lock_guard<std::mutex> lock(challenge_mutex);
        pending_challenges.erase(serial);
    }).detach();
}

bool PKIClient::signMessage(std::vector<uint8_t>& msg_data) {
    if (!has_valid_cert_.load(std::memory_order_acquire)) {
        return false;
    }

    try {
        // Create a new context for each signing operation
        EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
        if (!md_ctx) {
            std::cerr << "Failed to create message digest context" << std::endl;
            return false;
        }

        // Initialize for signing
        if (EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, key_.get()) <= 0) {
            std::cerr << "Failed to initialize signing operation" << std::endl;
            EVP_MD_CTX_free(md_ctx);
            return false;
        }

        // Add data to be signed
        if (EVP_DigestSignUpdate(md_ctx, msg_data.data(), msg_data.size()) <= 0) {
            std::cerr << "Failed to add data to signing context" << std::endl;
            EVP_MD_CTX_free(md_ctx);
            return false;
        }

        // Determine signature size
        size_t sig_len = 0;
        if (EVP_DigestSignFinal(md_ctx, NULL, &sig_len) <= 0) {
            std::cerr << "Failed to determine signature size" << std::endl;
            EVP_MD_CTX_free(md_ctx);
            return false;
        }

        // Allocate memory for signature
        std::vector<uint8_t> signature(sig_len);

        // Get the signature
        if (EVP_DigestSignFinal(md_ctx, signature.data(), &sig_len) <= 0) {
            std::cerr << "Failed to create signature" << std::endl;
            EVP_MD_CTX_free(md_ctx);
            return false;
        }

        EVP_MD_CTX_free(md_ctx);
        signature.resize(sig_len);
        msg_data = std::move(signature);
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Exception in signMessage: " << e.what() << std::endl;
        return false;
    }
}

bool PKIClient::validatePeer(json& msg) {
    try {
        ChallengeResponse response;
        response.deserialize(msg);

        // Check certificate
        if (response.certificate_pem.empty()) {
            throw std::runtime_error("Empty certificate received");
        }

        // Verify timestamp is recent
        auto now = std::chrono::system_clock::now();
        auto time_diff = std::chrono::duration_cast<std::chrono::seconds>(
            now - response.timestamp).count();
        if (std::abs(time_diff) > 30) {
            throw std::runtime_error("Challenge response expired");
        }

        // Convert PEM to X509
        BIO* bio = BIO_new_mem_buf(response.certificate_pem.c_str(), -1);
        if (!bio) throw std::runtime_error("Failed to create BIO");

        X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
        if (!cert) throw std::runtime_error("Failed to parse certificate");

        std::unique_ptr<X509, decltype(&X509_free)> cert_ptr(cert, X509_free);

        // Get public key from certificate
        EVP_PKEY* pkey = X509_get_pubkey(cert_ptr.get());
        if (!pkey) throw std::runtime_error("Failed to get public key");

        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey_ptr(pkey, EVP_PKEY_free);

        // Verify signature
        EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
        if (!md_ctx) throw std::runtime_error("Failed to create MD context");

        std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> md_ctx_ptr(md_ctx, EVP_MD_CTX_free);

        if (!EVP_DigestVerifyInit(md_ctx, nullptr, EVP_sha256(), nullptr, pkey_ptr.get()) ||
            !EVP_DigestVerifyUpdate(md_ctx, response.challenge_data.data(), response.challenge_data.size()) ||
            EVP_DigestVerifyFinal(md_ctx, response.signature.data(), response.signature.size()) != 1) {
            throw std::runtime_error("Signature verification failed");
        }

        return true;

    } catch (const json::exception& e) {
        std::cerr << "JSON parsing error: " << e.what() << std::endl;
        return false;
    } catch (const std::exception& e) {
        std::cerr << "Peer validation error: " << e.what() << std::endl;
        return false;
    }
}

// Helper function to wait for certificate
void PKIClient::waitForCertificate(std::atomic<bool>& running) {
    const std::chrono::seconds RETRY_DELAY(5);
    int attempt = 0;

    while (running && needsCertificate()) {
        try {
            if (attempt == 0 || attempt % 12 == 0) {
                if (!requestCertificate()) {
                    std::cerr << "Certificate request failed, will retry in "
                             << RETRY_DELAY.count() << " seconds" << std::endl;
                }
            }

            if (++attempt % 12 == 0) {
                std::cout << "Waiting for certificate... (" << attempt / 12
                         << " minutes)" << std::endl;
            }

            std::this_thread::sleep_for(RETRY_DELAY);

        } catch (const std::exception& e) {
            std::cerr << "Error while requesting certificate: " << e.what() << std::endl;
            std::this_thread::sleep_for(RETRY_DELAY);
        }
    }
}
