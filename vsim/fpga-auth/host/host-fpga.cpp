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
#define SERVER_IP "128.105.145.230"
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

void string_copy(char* dest, const char* src, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        dest[i] = src[i];
    }
}
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

    std::string rand_str, opc_str, autenb_str;

    signal(SIGINT, cleanup);
    signal(SIGTERM, cleanup);
    
    // Create or open shared memory object
    fd = shm_open(SHARED_MEM_NAME, O_CREAT | O_RDWR, 0666);
    if (fd == -1) {
        std::cerr << "Error opening shared memory: " << strerror(errno) << std::endl;
        return 1;
    }
    
    // Set the size of the shared memory
    if (ftruncate(fd, sizeof(SharedData)) == -1) {
        std::cerr << "Error setting size of shared memory: " << strerror(errno) << std::endl;
        close(fd);
        return 1;
    }
    
    // Map the shared memory object
    shared_data = static_cast<SharedData*>(
        mmap(NULL, sizeof(SharedData), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)
    );
    if (shared_data == MAP_FAILED) {
        std::cerr << "Error mapping shared memory: " << strerror(errno) << std::endl;
        close(fd);
        return 1;
    }
    
    // Initialize the shared data
    shared_data->command_ready = false;
    shared_data->response_ready = false;
    shared_data->auth_response_ready = false;
    
    std::cout << "vSIM started. Waiting for commands..." << std::endl;
    
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

