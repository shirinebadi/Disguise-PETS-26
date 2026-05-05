#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <stdexcept>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <thread>

#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sodium.h>
#include <curl/curl.h>

#define MSG_BLOCKSIZE 32
#define BLOCK_UP(len) (len+(MSG_BLOCKSIZE - (len%MSG_BLOCKSIZE)))

class NetworkError : public std::runtime_error {
public:
    explicit NetworkError(const std::string& message) : std::runtime_error(message) {}
};

class CryptoError : public std::runtime_error {
public:
    explicit CryptoError(const std::string& message) : std::runtime_error(message) {}
};

// Helper function to convert bytes to hex string
std::string bytesToHex(const unsigned char* data, size_t len) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for(size_t i = 0; i < len; i++) {
        ss << std::setw(2) << static_cast<int>(data[i]);
    }
    return ss.str();
}
std::vector<unsigned char> hexToBytes(const std::string& hex) {
        std::vector<unsigned char> bytes;
        for (size_t i = 0; i < hex.length(); i += 2) {
            bytes.push_back(std::stoi(hex.substr(i, 2), nullptr, 16));
        }
        return bytes;
    }


// CURL callback
size_t writeCallback(void* contents, size_t size, size_t nmemb, std::string* userp) {
    userp->append((char*)contents, size * nmemb);
    return size * nmemb;
}

class TrustedServer {
public:
    TrustedServer(const std::string& host = "0.0.0.0", uint16_t port = 1238)
        : host_(getPublicIP()), 
          port_(port) {
        if (sodium_init() < 0) {
            throw CryptoError("Libsodium initialization failed");
        }
    }

    void start() {
        generateKeypair();
        
        int server_socket = socket(AF_INET, SOCK_STREAM, 0);
        if (server_socket < 0) {
            throw NetworkError("Socket creation failed");
        }

        // Set socket options
        int opt = 1;
        if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
            close(server_socket);
            throw NetworkError("setsockopt failed");
        }

        sockaddr_in server_addr{};
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = INADDR_ANY;
        server_addr.sin_port = htons(port_);

        if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            close(server_socket);
            throw NetworkError("Binding failed");
        }

        if (listen(server_socket, SOMAXCONN) < 0) {
            close(server_socket);
            throw NetworkError("Listen failed");
        }

        std::cout << "Server is listening on all interfaces on port " << port_ << std::endl;
        std::cout << "Your public IP address is: " << host_ << std::endl;
        std::cout << "For external connections, ensure port " << port_ 
                  << " is forwarded to this machine" << std::endl;

        while (true) {
            sockaddr_in client_addr{};
            socklen_t client_len = sizeof(client_addr);
            
            int client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);
            if (client_socket < 0) {
                std::cerr << "Accept failed" << std::endl;
                continue;
            }

            std::cout << "Connected by " << inet_ntoa(client_addr.sin_addr) 
                      << ":" << ntohs(client_addr.sin_port) << std::endl;

            try {
                handleConnection(client_socket);
            } catch (const std::exception& e) {
                std::cerr << "Connection handler error: " << e.what() << std::endl;
            }

            close(client_socket);
        }
    }

private:
    static constexpr std::array<unsigned char, crypto_box_SECRETKEYBYTES> dev_secret_key = {
        0xd1, 0x2c, 0x26, 0x1e, 0x11, 0xed, 0x5d, 0xe4,
        0x10, 0x5e, 0x59, 0xf9, 0x7b, 0x7d, 0xc5, 0x09,
        0xa2, 0xb0, 0x93, 0x22, 0x32, 0xc6, 0x45, 0x07,
        0xea, 0x18, 0xd5, 0xc9, 0xe7, 0xbe, 0x86, 0xfe
    };
        static constexpr std::array<unsigned char, crypto_box_PUBLICKEYBYTES> dev_public_key = {
        0xbd, 0xcc, 0xd0, 0x68, 0xf1, 0x47, 0x36, 0x4f,
        0xcd, 0x39, 0x7a, 0x7a, 0x2c, 0x54, 0xb2, 0xc2,
        0x51, 0xc3, 0xf0, 0xa4, 0x53, 0xa4, 0x5a, 0x08,
        0x02, 0xc7, 0x06, 0xd8, 0x98, 0x62, 0x07, 0x6f
    };

    std::vector<unsigned char> Ack = {
  0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
};
    static std::string getPublicIP() {
        std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> curl(curl_easy_init(), curl_easy_cleanup);
        if (!curl) {
            throw NetworkError("CURL initialization failed");
        }

        std::string response;
        curl_easy_setopt(curl.get(), CURLOPT_URL, "https://api.ipify.org");
        curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, writeCallback);
        curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, &response);

        CURLcode res = curl_easy_perform(curl.get());
        if (res != CURLE_OK) {
            throw NetworkError("Failed to get public IP");
        }

        return response;
    }

    void generateKeypair() {
        if (crypto_kx_keypair(server_pk_.data(), server_sk_.data()) != 0) {
            throw CryptoError("Failed to generate keypair");
        }

        if (crypto_sign_keypair(server_spk_.data(), server_ssk_.data()) != 0) {
            throw CryptoError("Failed to generate keypair");
        }
    }

    void generateSessionKey(const std::vector<unsigned char>& client_pk) {
        if (crypto_kx_server_session_keys(
                session_rx_.data(),
                session_tx_.data(),
                server_pk_.data(),
                server_sk_.data(),
                client_pk.data()) != 0) {
            throw CryptoError("Failed to generate session keys");
        }
    }

    void handleConnection(int client_socket) {
        std::vector<unsigned char> buffer(1024);
        ssize_t bytes_received = recv(client_socket, buffer.data(), buffer.size(), 0);
        if (bytes_received <= 0) {
            throw NetworkError("Error receiving data");
        }

        std::cout << "Received Request total length: " << bytes_received << " bytes" << std::endl;
        std::cout << "Received request full hex: " 
                  << bytesToHex(buffer.data(), bytes_received) << std::endl;

        size_t clen = bytes_received - crypto_secretbox_NONCEBYTES;
        
        // Create a temporary buffer for the decrypted result
        std::vector<unsigned char> decrypted(clen - crypto_secretbox_MACBYTES);
        
        // Get pointer to nonce (it's at the end of the ciphertext)
        const unsigned char* nonce_ptr;
        
        // Attempt to decrypt using both public and private keys
        if (crypto_box_seal_open(
                buffer.data(),          // destination for decrypted message
                buffer.data(),             // source ciphertext
                bytes_received,            // length of ciphertext
                dev_public_key.data(),     // public key
                dev_secret_key.data()      // secret key
            ) != 0) {
            throw CryptoError("Decryption failed");
        }
        // Calculate plaintext length (excluding padding)
        size_t ptlen = 64;
        size_t unpadded_len;

        // Now decrypted[0..unpadded_len] contains the original message
        std::cout << "Decrypted message hex: " 
                  << bytesToHex(buffer.data(), bytes_received - crypto_box_SEALBYTES) << std::endl;


        // Extract nonce and client public key
        std::vector<unsigned char> nonce(
            buffer.begin(),
            buffer.begin() + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
        );
        
        std::vector<unsigned char> client_pk(
            buffer.begin() + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
            buffer.begin() + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + crypto_kx_PUBLICKEYBYTES
        );

        // std::vector<unsigned char> client_spk(
        //     buffer.begin() + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + crypto_kx_PUBLICKEYBYTES,
        //     buffer.begin() + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + crypto_kx_PUBLICKEYBYTES + crypto_sign_PUBLICKEYBYTES
        // );

        std::cout << "Received nonce: " << bytesToHex(nonce.data(), nonce.size()) << std::endl;
        std::cout << "Received client public key: " << bytesToHex(client_pk.data(), client_pk.size()) << std::endl;

        generateSessionKey(client_pk);

        const std::string hash = "366438333566626666656266656662646365643963373236376263623730313164633236363565333936366438323065313039616239633833316633356261303162663564353765313535383134373935373961646565393166316233613166373637393265323136326136346438333362373137646435626135336337663231";

        // Convert hex string to bytes
        std::vector<unsigned char> hash_bytes(hash.length() / 2);
        for(size_t i = 0; i < hash.length(); i += 2) {
            std::string byteString = hash.substr(i, 2);
            hash_bytes[i/2] = (unsigned char)std::stoi(byteString, nullptr, 16);
}

        // Sign nonce and hash
        std::vector<unsigned char> response;

        // Prepare response: nonce + server public key

        response.insert(response.end(), nonce.begin(), nonce.end());
        response.insert(response.end(), hash_bytes.begin(), hash_bytes.end());
        response.insert(response.end(), server_pk_.begin(), server_pk_.end());

        std::vector<unsigned char> encrypted_response(response.size() + crypto_box_SEALBYTES);

        if (crypto_box_seal(encrypted_response.data(), 
                       response.data(), 
                       response.size(), 
                       dev_public_key.data()) != 0) {
        throw std::runtime_error("Encryption failed");
    }


        if (send(client_socket, encrypted_response.data(), encrypted_response.size(), 0) < 0) {
            throw NetworkError("Error sending response");
        }

        std::cout << "Sent nonce: " << bytesToHex(nonce.data(), nonce.size()) << std::endl;
        std::cout << "Sent server public key: " << bytesToHex(server_pk_.data(), server_pk_.size()) << std::endl;

        std::cout << "Sent signing public key: " << bytesToHex(server_spk_.data(), server_spk_.size()) << std::endl;
        std::cout << "Sent hash: " << bytesToHex(hash_bytes.data(), hash_bytes.size()) << std::endl;
        std::cout << "Generated session key rx: " << bytesToHex(session_rx_.data(), session_rx_.size()) << std::endl;
        std::cout << "Generated session key tx: " << bytesToHex(session_tx_.data(), session_tx_.size()) << std::endl;

        // Receive attestation
        bytes_received = recv(client_socket, buffer.data(), buffer.size(), 0);
        if (bytes_received <= 0) {
            throw NetworkError("Error receiving attestation");
        }

        std::cout << "Received Attestation total length: " << bytes_received << " bytes" << std::endl;
        std::cout << "Received Attestation full hex: " 
                  << bytesToHex(buffer.data(), bytes_received) << std::endl;

        clen = bytes_received - crypto_secretbox_NONCEBYTES;
        
        // Create a temporary buffer for the decrypted result
        // std::vector<unsigned char> decrypted(clen - crypto_secretbox_MACBYTES);
        
        // Get pointer to nonce (it's at the end of the ciphertext)
        nonce_ptr = buffer.data() + clen;
        
        printf("Nonce: ");
        for(int i = 0; i < crypto_secretbox_NONCEBYTES; i++) {
            printf("%02x", nonce_ptr[i]);
        }
        printf("\n");

        // Attempt to decrypt
        if (crypto_secretbox_open_easy(
                buffer.data(),         // destination for decrypted message
                buffer.data(),            // source ciphertext
                clen,                     // length of ciphertext
                nonce_ptr,                // nonce
                session_rx_.data()        // decryption key
            ) != 0) {
            throw CryptoError("Decryption (unbox) failed");
        }

        // Calculate plaintext length (excluding padding)
        ptlen = 128;
        unpadded_len;

        // Unpad the decrypted message
        if (sodium_unpad(&unpadded_len, 
                        buffer.data(), 
                        ptlen, 
                        MSG_BLOCKSIZE) != 0) {
            throw CryptoError("Invalid message padding");
        }

        // Now decrypted[0..unpadded_len] contains the original message
        std::cout << "Successfully decrypted and unpadded message." << std::endl;

        // Verify hash
                std::cout << "Original message length: " << unpadded_len << " bytes" << std::endl;
        std::cout << "Decrypted message hex: " 
                  << bytesToHex(buffer.data(), unpadded_len) << std::endl;

        const std::string expected_hex = "240e875b996a9dd31461751fe0bed7686d20d9578bb0f3e64dfdd8c5c081679d4b25679715a52adcb0b9feb50a21cbd004c46323cceccdc86203aba06a2c089118";
        size_t expected_len = expected_hex.length() / 2;
        std::string actual_hex = bytesToHex(buffer.data(), expected_len);
        
        if (actual_hex == expected_hex) {
            std::cout << " Verification PASSED: First " << expected_len << " bytes match expected value" << std::endl;
        } else {
            std::cout << "Verification FAILED: First " << expected_len << " bytes do not match expected value" << std::endl;
            std::cout << "Expected: " << expected_hex << std::endl;
            std::cout << "Actual:   " << actual_hex << std::endl;
        }

        // Send Ack

        size_t buf_padded_len;
        size_t total_size = BLOCK_UP(Ack.size()) + crypto_secretbox_MACBYTES + crypto_secretbox_NONCEBYTES;
        
        // Resize buffer to accommodate padded message + MAC + nonce
        buffer.resize(total_size);
        
        // Copy message to buffer
        std::copy(Ack.begin(), Ack.end(), buffer.begin());
        
        // Pad the message
        if (sodium_pad(&buf_padded_len, 
                      buffer.data(), 
                      Ack.size(), 
                      MSG_BLOCKSIZE, 
                      BLOCK_UP(Ack.size())) != 0) {
            throw std::runtime_error("[CPP] Unable to pad message");
        }
        
        // Get pointer to nonce location (after padded message + MAC)
        unsigned char* nonceptr = buffer.data() + crypto_secretbox_MACBYTES + buf_padded_len;
        
        // Generate random nonce
        randombytes_buf(nonceptr, crypto_secretbox_NONCEBYTES);
        
        // Encrypt the message
        if (crypto_secretbox_easy(buffer.data(),      // destination
                                buffer.data(),        // source
                                buf_padded_len,       // message length
                                nonceptr,             // nonce
                                session_tx_.data()) != 0) {   // key
            throw std::runtime_error("[CPP] Unable to encrypt message");
        }
        
        std::cout << "[CPP] Successfully Encrypted" << std::endl;
        if (send(client_socket, buffer.data(), 72, 0) < 0) {
            throw NetworkError("Error sending Ack");
        }
    }

    static int verifyPadding(const std::vector<unsigned char>& data, size_t blocksize) {
        if (data.empty() || data.size() % blocksize != 0) {
            throw CryptoError("Invalid padded length");
        }

        unsigned char padding_len = data.back();
        if (padding_len == 0 || padding_len > blocksize) {
            throw CryptoError("Invalid padding value");
        }

        for (size_t i = 0; i < padding_len; i++) {
            if (data[data.size() - 1 - i] != padding_len) {
                throw CryptoError("Invalid padding bytes");
            }
        }

        return static_cast<int>(data.size() - padding_len);
    }

private:
    std::string host_;
    uint16_t port_;
    std::array<unsigned char, crypto_kx_SECRETKEYBYTES> server_sk_;
    std::array<unsigned char, crypto_kx_PUBLICKEYBYTES> server_pk_;
    std::array<unsigned char, crypto_sign_SECRETKEYBYTES> server_ssk_;
    std::array<unsigned char, crypto_sign_PUBLICKEYBYTES> server_spk_;
    std::array<unsigned char, crypto_kx_SESSIONKEYBYTES> session_rx_;
    std::array<unsigned char, crypto_kx_SESSIONKEYBYTES> session_tx_;
};

int main() {
    try {
        if (curl_global_init(CURL_GLOBAL_ALL) != 0) {
            throw std::runtime_error("CURL global initialization failed");
        }

        TrustedServer server;
        server.start();

    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    }

    curl_global_cleanup();
    return 0;
}