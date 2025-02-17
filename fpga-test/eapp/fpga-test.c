#include "app/eapp_utils.h"
#include "string.h"
#include "syscall.h"
#include "malloc.h"
#include "sodium.h"
#include "channel.h"
#include "hacks.h"
#include <time.h>
#include <sys/time.h>
#include "edge_wrapper.h"
#include "usim.h"

unsigned char ck[16];
unsigned char ik[16];
unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
unsigned char received_nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
char provider_hash[129] = "6d835fbffebfefbdced9c7267bcb7011dc2665e3966d820e109ab9c831f35ba01bf5d57e15581479579adee91f1b3a1f76792e2162a64d833b717dd5ba53c7f218";
char received_hash[129];
unsigned char signature[crypto_sign_BYTES];
unsigned char received_signature[crypto_sign_BYTES];

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

void establish_secure_channel(){

  ocall_print_string("Initializing vSIM channel\n");
  init();

  // Generate Nonce
  randombytes_buf(nonce, sizeof nonce);

  // Call to send RA request
  unsigned char send_buffer[1024];
  memcpy(send_buffer, nonce, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES );
  memcpy(send_buffer + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES , server_pk, crypto_kx_PUBLICKEYBYTES);

  size_t initiate_buff_len = 56+crypto_box_SEALBYTES;
  unsigned char* initiate_buff = malloc(initiate_buff_len);
  if(initiate_buff == NULL){
      ocall_print_string("Initiate Buff too large to allocate, no reply sent\n");
    }
  
  asymmetric_box(send_buffer, 56, initiate_buff, dev_public_key);
  ocall_send_ra_req(initiate_buff, 104);

  ocall_print_string("[C] Successfully sent nonce and public key\n");
  
  // Wait for server key and report
  struct edge_data resp;
  ocall_wait_for_message(&resp);
  void* data_copy = malloc(resp.size);
  copy_from_shared(data_copy, resp.offset, resp.size);

  ocall_print_string("[C] Successfully Recieved provider Response\n");

  unsigned char* response_buff = malloc(1024);
  if(response_buff == NULL){
      ocall_print_string("Initiate Buff too large to allocate, no reply sent\n");
    }
  
  asymmetric_unbox((unsigned char*)data_copy, 233, response_buff);
  ocall_print_string("[C] Successfully Decrypted provider Response\n");

  memcpy(received_nonce, (unsigned char*)response_buff, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  ocall_print_string("[C] Nonce extracted\n");

  // Verify Nonce
  if (sodium_memcmp(nonce, received_nonce, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) == 0) {
    ocall_print_string("[C] Nonce verified\n");
  } else{
      ocall_print_string("[C] Error in Received Nonce\n");
      EAPP_RETURN(1);
  }
  print_hex(received_nonce, crypto_aead_xchacha20poly1305_IETF_NPUBBYTES);

// Extract Provider Quote
  memcpy(received_hash, 
  (unsigned char*)response_buff + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, 
  129);
  
  // Verify Quote
  print_hex(provider_hash, 129);
  if (memcmp(received_hash, provider_hash, 129) == 0){
    ocall_print_string("[C] Provider Quote verified\n");
  } else{
      ocall_print_string("[C] Error in Received Quote\n");
      EAPP_RETURN(1);
  }

   unsigned char dest[crypto_aead_xchacha20poly1305_IETF_NPUBBYTES+129];
   memcpy(dest, nonce, crypto_aead_xchacha20poly1305_IETF_NPUBBYTES);
    
    // Copy hash
    print_hex(provider_hash, 129);
    memcpy(dest + crypto_aead_xchacha20poly1305_IETF_NPUBBYTES, provider_hash, 129);

  // Extract server public key
  memcpy(client_pk, 
           (unsigned char*)response_buff + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + 129, 
           crypto_kx_PUBLICKEYBYTES);
  ocall_print_string("[C] Provider Pub key extracted\n");

  // Generate Session Keys
  generate_session_keys();
  ocall_print_string("[C] Successfully generated session keys.\n");

  // Send encrypted Quote
  size_t reply_len = crypto_secretbox_MACBYTES + BLOCK_UP(96) + crypto_secretbox_NONCEBYTES;
  unsigned char* reply_buffer = malloc(reply_len);
  if(reply_buffer == NULL){
      ocall_print_string("Reply too large to allocate, no reply sent\n");
    }

  char attestation_buffer[2048];
  attest_enclave((void*) attestation_buffer, nonce, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  
  memcpy(send_buffer, attestation_buffer, 64 + 8 + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

  channel_box(send_buffer, 96, reply_buffer, tx);
  ocall_send_buffer(reply_buffer, 168);

  // Wait for Ack
  ocall_wait_for_message(&resp);

  copy_from_shared(data_copy, resp.offset, resp.size);
  size_t ack_len;
  ocall_print_string("decrypting ack");
  channel_unbox((unsigned char*)data_copy, 72, &ack_len);

  // ocall_print_string(ack_len);

  if (sodium_memcmp(data_copy, Ack, 8) != 0) {
        ocall_print_string("[C] Provider Didn't Acknowledge.\n");
        EAPP_RETURN(1);
    }
  
  EAPP_RETURN(0);

}


void EAPP_ENTRY eapp_entry(){
  unsigned char opc_o[16] = {0};  // Initialize to zeros
  unsigned char rand[16] = {0}; 
  unsigned char res_o[8];
  unsigned char ak_xor_sqn[6];
  unsigned char autn_enb[16] = {0};
    
  struct edge_data resp;
    ocall_wait_for_challenge(&resp);
    void* data_copy = malloc(resp.size);
    copy_from_shared(data_copy, resp.offset, resp.size);

    memcpy(rand, data_copy, 16);
    // Next 16 bytes are opc
    memcpy(opc_o, data_copy + 16, 16);

  memcpy(autn_enb, data_copy + 32, 16);
  ocall_print_string("------------autnenb:\n");
  print_hex(autn_enb, 16);
    if (gen_auth_res_milenage(opc_o, rand, autn_enb, res_o, 8, ak_xor_sqn) != 0){
      ocall_print_string("Error in f2345");
    }

    unsigned char* send_buffer = malloc(92);
    if(send_buffer == NULL){
      ocall_print_string("Reply too large to allocate, no reply sent\n");
    }

    // res_o
    memcpy(send_buffer, res_o, 8);
    // ak_xor_sqn
    memcpy(send_buffer+8, ak_xor_sqn, 6);
    // ck
    memcpy(send_buffer +8 + 6, ck,16);
    //ik
    memcpy(send_buffer +8 + 6 + 16, ik,16);



    ocall_send_challenge_response(send_buffer, 46);

  EAPP_RETURN(0);
}