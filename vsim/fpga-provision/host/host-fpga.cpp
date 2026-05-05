#include "edge_wrapper.h"
#include "edge_common.h"
#include "keystone.h"
#include <string>
#include <iostream>
#include <fstream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <cstdio>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <string>
#include <iostream>
#include <fstream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <cstdio>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <string>
#include <cstring>
#include <iostream>
#include <csignal>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "common/sha3.h"
#include "host/keystone.h"
#include "verifier/report.h"
#include "verifier/test_dev_key.h"

#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <atomic>

#include <cerrno>
#include <cstdio>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>


#define PRINT_MESSAGE_BUFFERS 1
#define SERVER_IP "128.105.145.215"
#define SERVER_PORT 1238
int sock;
#define BUFFERLEN 4096
byte local_buffer[BUFFERLEN];
char* eapp_file;
  char* rt_file;
  char* ld_file;
 char* sm_bin_file;


 uint8_t rand_bytes[16] = {0};
uint8_t opc_bytes[16] = {0};
uint8_t autenb_bytes[16] = {0};

const char* SHARED_MEM_NAME = "/test_shared_memory";

// Shared data structure
struct AuthData {
    unsigned char rand_bytes[16];    // 16 raw bytes for RAND
    unsigned char opc_bytes[16];     // 16 raw bytes for OPC
    unsigned char autenb_bytes[16];    // 16 raw bytes for AUTN
};

// Command types
enum CommandType {
    CMD_NONE = 0,
    CMD_AUTHENTICATE = 1,
    CMD_SWITCH = 2,
    CMD_EXIT = 3
};

// Shared data structure
struct SharedData {
    std::atomic<bool>  command_ready;        // Flag indicating a command is ready to be processed
    std::atomic<bool>  response_ready;       // Flag indicating a response is ready to be read
    std::atomic<bool>  auth_response_ready;
    CommandType command_type;  // Type of command
    AuthData auth_data;        // Authentication data for Authenticate command
    uint8_t res[8];
    uint8_t ak_xor_sqn[6];
    uint8_t ck[16];
    uint8_t ik[16];
    char response[256];
};

// Global pointer to shared memory for signal handler access
SharedData* shared_data = nullptr;
int fd = -1;

uint8_t res[8] = {0};
uint8_t ak_xor_sqn[6] = {0};
uint8_t ck[16] = {0};
uint8_t ik[16] = {0};
// // Simple string copy function to replace memcpy
void string_copy(char* dest, const char* src, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        dest[i] = src[i];
    }
}
// void
// compute_expected_enclave_hash(byte* expected_enclave_hash) {
//   Keystone::Enclave::measure((char*) expected_enclave_hash, eapp_file, rt_file, ld_file);
// }

// // void
// // compute_expected_sm_hash(byte* expected_sm_hash) {
// //   // It is important to make sure the size of the SM buffer we are
// //   // measuring is the same as the size of the SM buffer allocated by
// //   // the bootloader. See keystone/bootrom/bootloader.c for how it is
// //   // computed in the bootloader.
// //   const size_t sanctum_sm_size = 0x1ff000;
// //   std::vector<byte> sm_content(sanctum_sm_size, 0);

// //   {
// //     // Reading SM content from file.
// //     FILE* sm_bin = fopen(sm_bin_file, "rb");
// //     if (!sm_bin)
// //       throw std::runtime_error(
// //           "Error opening sm_bin_file_: " + sm_bin_file + ", " +
// //           std::strerror(errno));
// //     if (fread(sm_content.data(), 1, sm_content.size(), sm_bin) <= 0)
// //       throw std::runtime_error(
// //           "Error reading sm_bin_file_: " + sm_bin_file + ", " +
// //           std::strerror(errno));
// //     fclose(sm_bin);
// //   }

// //   {
// //     // The actual SM hash computation.
// //     hash_ctx_t hash_ctx;
// //     hash_init(&hash_ctx);
// //     hash_extend(&hash_ctx, sm_content.data(), sm_content.size());
// //     hash_finalize(expected_sm_hash, &hash_ctx);
// //   }
// // }

unsigned long print_string(char* str) {
  return printf("Enclave said: \"%s\"\n", str);
}

void cleanup(int sig) {
    std::cout << "Cleaning up shared memory..." << std::endl;
    if (shared_data != nullptr && shared_data != MAP_FAILED) {
        munmap(shared_data, sizeof(SharedData));
    }
    if (fd != -1) {
        close(fd);
    }
    shm_unlink(SHARED_MEM_NAME);
    exit(sig);
}

#define BUFFER_SIZE 1024

byte* recv_buffer(size_t* len) {
    byte* buffer = (byte*)malloc(BUFFER_SIZE);
    if (buffer == NULL) {
        printf("Error: Failed to allocate memory for buffer\n");
        return NULL;
    }

    ssize_t received = read(sock, buffer, BUFFER_SIZE);
    if (received < 0) {
        printf("Error: Failed to read from socket. errno: %d (%s)\n", errno, strerror(errno));
        free(buffer);
        return NULL;
    } else if (received == 0) {
        printf("Connection closed by server\n");
        free(buffer);
        return NULL;
    }

    *len = received;
    return buffer;
}

void send_buffer(void* data, size_t len){
    // Report report;
    // report.fromBytes((unsigned char*)data);
    // std::cout << "Report (" << len << " bytes):" << std::endl;
    // report.printPretty();
    // byte expected_enclave_hash[MDSIZE];
    // compute_expected_enclave_hash(expected_enclave_hash);

    // byte expected_sm_hash[MDSIZE];
    // compute_expected_sm_hash(expected_sm_hash);

    const unsigned char* bytes = static_cast<const unsigned char*>(data);
    
    //std::cout << "Data (" << len << " bytes):" << std::endl;
    
    // Print hexadecimal representation
    // for (size_t i = 0; i < len; ++i) {
    //     std::cout << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(bytes[i]) << " ";
    //     if ((i + 1) % 16 == 0 || i == len - 1) {
    //         std::cout << std::endl;
    //     }
    // }

    // std::cout << "Enclave Hash (" << MDSIZE << " bytes):" << std::endl;
    
    // // Print hexadecimal representation
    // for (size_t i = 0; i < MDSIZE; ++i) {
    //     std::cout << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(expected_enclave_hash[i]) << " ";
    //     if ((i + 1) % 16 == 0 || i == len - 1) {
    //         std::cout << std::endl;
    //     }
    // }
    
    // std::cout << "SM Hash (" << len << " bytes):" << std::endl;

    // for (size_t i = 0; i < len; ++i) {
    //     std::cout << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(expected_sm_hash[i]) << " ";
    //     if ((i + 1) % 16 == 0 || i == len - 1) {
    //         std::cout << std::endl;
    //     }
    // }

    size_t total_sent = 0;
while (total_sent < len) {
    ssize_t sent_bytes = send(sock, static_cast<const char*>(data) + total_sent, len - total_sent, MSG_NOSIGNAL);
    if (sent_bytes < 0) {
        if (errno == EINTR) continue;  // Interrupted, try again
        std::cerr << "Send failed: " << strerror(errno) << std::endl;
        break;
    } else if (sent_bytes == 0) {
        std::cerr << "Connection closed by peer" << std::endl;
        break;
    }
    total_sent += sent_bytes;
}

if (total_sent == len) {
    std::cout << "Sent all " << total_sent << " bytes successfully" << std::endl;
} else {
    std::cerr << "Only sent " << total_sent << " out of " << len << " bytes" << std::endl;
}
}


encl_message_t wait_for_message(){
  size_t len = 0;
  void* m = recv_buffer(&len);
  
//   while (m[len] != '\0') ++len;
//   len += 1;  // +1 for null terminator
  
  char* buffer = static_cast<char*>(malloc(len));
  if (buffer == NULL) {
      // Handle memory allocation failure
      printf("Memory allocation failed\n");
      exit(1);
  }
  string_copy(buffer, (const char*)m, len);
  //printf("Message Received\n");
  
  encl_message_t message;
  message.host_ptr = buffer;
  message.len = len;
  return message;
}

void send_ra_req(void* data, size_t len) {
    printf("[EH] Sending Attestation Req:\n");

    const unsigned char* bytes = static_cast<const unsigned char*>(data);
    
    std::cout << "Data (" << len << " bytes):" << std::endl;
    
    // Print hexadecimal representation
    for (size_t i = 0; i < len; ++i) {
        std::cout << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(bytes[i]) << " ";
        if ((i + 1) % 16 == 0 || i == len - 1) {
            std::cout << std::endl;
        }
    }

    // Create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        std::cerr << "Socket creation error" << std::endl;
        return;
    }

    // Set up server address
    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(SERVER_PORT);

    // Convert IPv4 and IPv6 addresses from text to binary form
    if (inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0) {
        std::cerr << "Invalid address/ Address not supported" << std::endl;
        close(sock);
        return;
    }

    // Connect to the server
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        std::cerr << "Connection Failed" << std::endl;
        close(sock);
        return;
    }

    size_t total_sent = 0;
while (total_sent < len) {
    ssize_t sent_bytes = send(sock, static_cast<const char*>(data) + total_sent, len - total_sent, MSG_NOSIGNAL);
    if (sent_bytes < 0) {
        if (errno == EINTR) continue;  // Interrupted, try again
        std::cerr << "Send failed: " << strerror(errno) << std::endl;
        break;
    } else if (sent_bytes == 0) {
        std::cerr << "Connection closed by peer" << std::endl;
        break;
    }
    total_sent += sent_bytes;
}

if (total_sent == len) {
    std::cout << "Sent all " << total_sent << " bytes successfully" << std::endl;
} else {
    std::cerr << "Only sent " << total_sent << " out of " << len << " bytes" << std::endl;
}

}

encl_message_t wait_for_resp(){
  printf("[EH] Waiting for Server Response:\n");
  
//   ssize_t received_bytes = recv(sock, response.data(), response.size(), 0);

//   // Nonce
//   // Public Key
//   // Report
//   // Signatures
  
// if (received_bytes == 0) {
//     std::cout << "Server closed the connection" << std::endl;
//     return encl_message_t{nullptr, 0};
// }

// std::cout << "Received " << received_bytes << " bytes" << std::endl;

// // Resize the vector to the actual number of bytes received
// response.resize(received_bytes);


// // Allocate memory for the message
// uint8_t* buffer = new uint8_t[received_bytes];
// std::memcpy(buffer, response.data(), received_bytes);
// std::cout << "Message Received" << std::endl;
// std::cout << "Received data:" << std::endl;
//     for (size_t i = 0; i < received_bytes; ++i) {
//         printf("%02X ", (char)buffer[i]);
//         if ((i + 1) % 16 == 0 || i == received_bytes - 1) {
//             std::cout << std::endl;
//         }
//     }
//     std::cout << std::endl;
size_t len;

void* buffer = recv_buffer(&len);
if (buffer == NULL) {
    printf("[EH] Error: recv_buffer returned NULL\n");
    return (encl_message_t){NULL, 0};
  }
  
  printf("[EH] Received buffer of length %zu\n", len);
encl_message_t message;
message.host_ptr = buffer;
message.len = len;
printf("[EH] Sent Server Response.\n");
return message;
}

void send_challenge_response(void* data, size_t len)
{
    printf("Challenge Response Recieved in Normal World.\n");

    const unsigned char* bytes = static_cast<const unsigned char*>(data);

    memcpy(shared_data->res, data, 8);
    memcpy(shared_data->ak_xor_sqn, data + 8, 6);
    memcpy(shared_data->ck, data + 8 + 6, 16);
    memcpy(shared_data->ik, data + 8 + 6 + 16, 16);
    
    //std::atomic_thread_fence(std::memory_order_release);
    printf("Fence set and now Ready to set response ready flag\n");

shared_data->auth_response_ready.store(true, std::memory_order_release);
    
sleep(10);
}

encl_message_t send_challenge_to_vSIM(){

    while(true){
    if (shared_data->command_ready.load(std::memory_order_acquire)) {
        std::cout << "Received command type: " << shared_data->command_type << std::endl;
        
        // Process based on command type
        switch (shared_data->command_type) {
            case CMD_AUTHENTICATE:{
                std::cout << "Processing authentication request" << std::endl;
                shared_data->auth_response_ready = false;
    
                memcpy(rand_bytes, shared_data->auth_data.rand_bytes, 16);
                memcpy(opc_bytes, shared_data->auth_data.opc_bytes, 16);
                memcpy(autenb_bytes, shared_data->auth_data.autenb_bytes, 16);
    
                size_t len = 48; // 16 bytes each for rand, opc, and autenb
                char* buffer = static_cast<char*>(malloc(len));
    
                if (buffer != NULL) {
                    // Copy the byte arrays into the buffer
                    memcpy(buffer, rand_bytes, 16);
                    memcpy(buffer + 16, opc_bytes, 16);
                    memcpy(buffer + 32, autenb_bytes, 16);
                    
                    // Set response as ready
                    shared_data->command_ready.store(false, std::memory_order_release);
                    
                    
                    // Prepare the message to return
                    encl_message_t message;
                    message.host_ptr = buffer;
                    message.len = len;
                    
                    return message;
                }
                break; 
            }
                
            case CMD_SWITCH:
            break;
        }
    
    }
    sleep(1);
    }
    }

int main(int argc, char** argv) {

    
  Keystone::Enclave enclave;
  Keystone::Params params;
// params.setFreeMemSize(4096 * 1024);
//   params.setUntrustedSize(1024 * 1024);
  enclave.init(argv[1], argv[2], argv[3], params);

    size_t untrusted_size = 2 * 1024 * 1024;
  size_t freemem_size   = 48 * 1024 * 1024;
  bool retval_exist     = false;
  unsigned long retval  = 0;

  edge_init(&enclave);
  
  printf("Starting Enclave...\n");
 
  enclave.run();



    // Return the string length as success code
    return 0;
}

