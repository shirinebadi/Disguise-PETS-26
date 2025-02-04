#include "app/eapp_utils.h"
#include "string.h"
#include "syscall.h"
#include "malloc.h"
#include <time.h>
#include <sys/time.h>
#include "edge_wrapper.h"
#include "sodium.h"
#include "hacks.h"
#include "usim.h"


// unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
// unsigned char received_nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
// char provider_hash[129] = "6d835fbffebfefbdced9c7267bcb7011dc2665e3966d820e109ab9c831f35ba01bf5d57e15581479579adee91f1b3a1f76792e2162a64d833b717dd5ba53c7f218";
// char received_hash[129];
// unsigned char signature[crypto_sign_BYTES];
// unsigned char received_signature[crypto_sign_BYTES];
unsigned char server_pk[crypto_kx_PUBLICKEYBYTES], server_sk[crypto_kx_SECRETKEYBYTES];
void print_hex(unsigned char* buffer, size_t size){
    const char hex_chars[] = "0123456789abcdef";
    char hex_string[size*2 + 1];

    for (size_t i = 0; i < size; i++) {
        hex_string[i * 2] = hex_chars[(buffer[i] >> 4) & 0xF];
        hex_string[i * 2 + 1] = hex_chars[buffer[i] & 0xF];
    }
    hex_string[size*2] = '\0';  

    ocall_print_string(hex_string);
}
void print_h(unsigned char* buffer, size_t size){
    const char hex_chars[] = "0123456789abcdef";
    char hex_string[size*2 + 1];

    for (size_t i = 0; i < size; i++) {
        hex_string[i * 2] = hex_chars[(buffer[i] >> 4) & 0xF];
        hex_string[i * 2 + 1] = hex_chars[buffer[i] & 0xF];
    }
    hex_string[size*2] = '\0';  

    ocall_print_string(hex_string);
}

// void establish_secure_channel(){

//   ocall_print_string("Initializing vSIM channel\n");
//   init();

//   // Generate Nonce
//   randombytes_buf(nonce, sizeof nonce);

//   // Call to send RA request
//   unsigned char send_buffer[1024];
//   memcpy(send_buffer, nonce, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES );
//   memcpy(send_buffer + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES , server_pk, crypto_kx_PUBLICKEYBYTES);

//   size_t initiate_buff_len = 56+crypto_box_SEALBYTES;
//   unsigned char* initiate_buff = malloc(initiate_buff_len);
//   if(initiate_buff == NULL){
//       ocall_print_string("Initiate Buff too large to allocate, no reply sent\n");
//     }
  
//   asymmetric_box(send_buffer, 56, initiate_buff, dev_public_key);
//   ocall_send_ra_req(initiate_buff, 104);

//   ocall_print_string("[C] Successfully sent nonce and public key\n");
  
//   // Wait for server key and report
//   struct edge_data resp;
//   ocall_wait_for_message(&resp);
//   void* data_copy = malloc(resp.size);
//   copy_from_shared(data_copy, resp.offset, resp.size);

//   ocall_print_string("[C] Successfully Recieved provider Response\n");

//   unsigned char* response_buff = malloc(1024);
//   if(response_buff == NULL){
//       ocall_print_string("Initiate Buff too large to allocate, no reply sent\n");
//     }
  
//   asymmetric_unbox((unsigned char*)data_copy, 233, response_buff);
//   ocall_print_string("[C] Successfully Decrypted provider Response\n");

//   memcpy(received_nonce, (unsigned char*)response_buff, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
//   ocall_print_string("[C] Nonce extracted\n");

//   // Verify Nonce
//   if (sodium_memcmp(nonce, received_nonce, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) == 0) {
//     ocall_print_string("[C] Nonce verified\n");
//   } else{
//       ocall_print_string("[C] Error in Received Nonce\n");
//       EAPP_RETURN(1);
//   }
//   print_hex(received_nonce, crypto_aead_xchacha20poly1305_IETF_NPUBBYTES);

// // Extract Provider Quote
//   memcpy(received_hash, 
//   (unsigned char*)response_buff + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, 
//   129);
  
//   // Verify Quote
//   print_hex(provider_hash, 129);
//   if (memcmp(received_hash, provider_hash, 129) == 0){
//     ocall_print_string("[C] Provider Quote verified\n");
//   } else{
//       ocall_print_string("[C] Error in Received Quote\n");
//       EAPP_RETURN(1);
//   }

//    unsigned char dest[crypto_aead_xchacha20poly1305_IETF_NPUBBYTES+129];
//    memcpy(dest, nonce, crypto_aead_xchacha20poly1305_IETF_NPUBBYTES);
    
//     // Copy hash
//     print_hex(provider_hash, 129);
//     memcpy(dest + crypto_aead_xchacha20poly1305_IETF_NPUBBYTES, provider_hash, 129);

//   // Extract server public key
//   memcpy(client_pk, 
//            (unsigned char*)response_buff + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + 129, 
//            crypto_kx_PUBLICKEYBYTES);
//   ocall_print_string("[C] Provider Pub key extracted\n");

//   // Generate Session Keys
//   generate_session_keys();
//   ocall_print_string("[C] Successfully generated session keys.\n");

//   // Send encrypted Quote
//   size_t reply_len = crypto_secretbox_MACBYTES + BLOCK_UP(96) + crypto_secretbox_NONCEBYTES;
//   unsigned char* reply_buffer = malloc(reply_len);
//   if(reply_buffer == NULL){
//       ocall_print_string("Reply too large to allocate, no reply sent\n");
//     }

//   char attestation_buffer[2048];
//   attest_enclave((void*) attestation_buffer, nonce, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  
//   memcpy(send_buffer, attestation_buffer, 64 + 8 + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

//   channel_box(send_buffer, 96, reply_buffer, tx);
//   ocall_send_buffer(reply_buffer, 168);

//   // Wait for Ack
//   ocall_wait_for_message(&resp);

//   copy_from_shared(data_copy, resp.offset, resp.size);
//   size_t ack_len;
//   ocall_print_string("decrypting ack");
//   channel_unbox((unsigned char*)data_copy, 72, &ack_len);

//   // ocall_print_string(ack_len);

//   if (sodium_memcmp(data_copy, Ack, 8) != 0) {
//         ocall_print_string("[C] Provider Didn't Acknowledge.\n");
//         EAPP_RETURN(1);
//     }
  
//   EAPP_RETURN(0);

// }

// long get_ms(void) {     
//     struct timeval tv;
//     gettimeofday(&tv, NULL);
//     return (tv.tv_sec * 1000) + (tv.tv_usec / 1000);
// }

// // Method 2: Using gettimeofday()
// long get_ms_gettimeofday(void) {
//     struct timeval tv;
//     gettimeofday(&tv, NULL);
//     return (tv.tv_sec * 1000) + (tv.tv_usec / 1000);
// }

// void ltoa(long num, char* str) {
//     int i = 0;
//     int is_negative = 0;
    
//     if (num < 0) {
//         is_negative = 1;
//         num = -num;
//     }
    
//     if (num == 0) {
//         str[i++] = '0';
//         str[i] = '\0';
//         return;
//     }
    
//     while (num != 0) {
//         str[i++] = (num % 10) + '0';
//         num = num / 10;
//     }
    
//     if (is_negative) {
//         str[i++] = '-';
//     }
    
//     str[i] = '\0';
    
//     int start = 0;
//     int end = i - 1;
//     while (start < end) {
//         char temp = str[start];
//         str[start] = str[end];
//         str[end] = temp;
//         start++;
//         end--;
//     }
// }

void EAPP_ENTRY eapp_entry(){
  // ocall_print_string("Computing SIM Challenge\n");
  ocall_print_string("Testing Libsodium...");
  magic_random_init();
    randombytes_set_implementation(&randombytes_salsa20_implementation);
    
    if (sodium_init() < 0) {
        EAPP_RETURN(1);
    }

    if (crypto_kx_keypair(server_pk, server_sk) != 0) {
        EAPP_RETURN(1);
    }
  ocall_print_string("Successfuly generated server public/private keys...");
  ocall_print_string("Priniting server private key:");
  print_hex(server_sk, crypto_kx_SECRETKEYBYTES);
  ocall_print_string("Printing Server Pub key");
  print_hex(server_pk, crypto_kx_PUBLICKEYBYTES);


  // struct timeval start, end;
    
  //  gettimeofday(&start, NULL);
  // establish_secure_channel();
    unsigned char opc_o[] = {0xcd, 0x63, 0xcb, 0x71, 0x95, 0x4a, 0x9f, 0x4e, 0x48, 0xa5, 0x99, 0x4e, 0x37, 0xa0, 0x2b, 0xaf};
    // unsigned char k[]    = {0x46, 0x5b, 0x5c, 0xe8, 0xb1, 0x99, 0xb4, 0x9f, 0xaa, 0x5f, 0x0a, 0x2e, 0xe2, 0x38, 0xa6, 0xbc};
    unsigned char rand[] = {0x23, 0x55, 0x3c, 0xbe, 0x96, 0x37, 0xa8, 0x9d, 0x21, 0x8a, 0xe6, 0x4d, 0xae, 0x47, 0xbf, 0x35};
    unsigned char res_o[8];
    unsigned char ak_xor_sqn[6];
    unsigned char autn_enb[] = {    0x55, 0xf3, 0x28, 0xb4, 0x35, 0x77,  // SQN ⊕ AK 
    0xb9, 0xb9,                           // AMF
    0xa8, 0xfe, 0xd0, 0x17, 0xc4, 0xc8, 0xab, 0xee};
    // unsigned char ck_o[16];
    // unsigned char ik_o[16];
    // unsigned char ak_o[6];
    // unsigned char mac_o[8];
    // uint8_t sqn[]  = {0xff, 0x9b, 0xb4, 0xd0, 0xb6, 0x07};
    // uint8_t amf[]  = {0xb9, 0xb9};

    // if (liblte_security_milenage_f2345(k, opc_o, rand, res_o, ck_o, ik_o, ak_o) != 0){
    //   ocall_print_string("Error in f2345");
    // }
    // print_hex(k, 16);
    // print_hex(res_o, 8);
    // print_hex(ck_o, 16);
    // print_hex(ik_o,16);
    // print_hex(ak_o,6);

    // if (liblte_security_milenage_f1(k, opc_o, rand, sqn, amf, mac_o) != 0){
    //   ocall_print_string("Error in f1");
    // }
    // print_hex(mac_o, 8);

    // if (gen_auth_res_milenage(opc_o, rand, autn_enb, res_o, 8, ak_xor_sqn) != 0){
    //   ocall_print_string("Error in f2345");
    // }



    // gettimeofday(&end, NULL);
    
    // // Calculate time difference in different units
    // long seconds = end.tv_sec - start.tv_sec;
    // long microseconds = end.tv_usec - start.tv_usec;
    
    // // Adjust for microsecond overflow
    // if (microseconds < 0) {
    //     seconds--;
    //     microseconds += 1000000;
    // }
    
    // // Convert to milliseconds
    // long milliseconds = (seconds * 1000) + (microseconds / 1000);
    
    // // Print each component
    // char debug[100];
    // ltoa(seconds, debug);
    // ocall_print_string("Seconds: ");
    // ocall_print_string(debug);
    // ocall_print_string("\n");
    
    // ltoa(microseconds, debug);
    // ocall_print_string("Microseconds: ");
    // ocall_print_string(debug);
    // ocall_print_string("\n");
    
    // ltoa(milliseconds, debug);
    // ocall_print_string("Milliseconds: ");
    // ocall_print_string(debug);
    // ocall_print_string("\n");

  EAPP_RETURN(0);
}