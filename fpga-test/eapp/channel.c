#include "eapp_utils.h"
#include "sodium.h"
#include "channel.h"
#include "string.h"

unsigned char server_pk[crypto_kx_PUBLICKEYBYTES], server_sk[crypto_kx_SECRETKEYBYTES];
unsigned char server_spk[crypto_sign_PUBLICKEYBYTES], server_ssk[crypto_sign_SECRETKEYBYTES];
unsigned char client_pk[crypto_kx_PUBLICKEYBYTES];
unsigned char client_spk[crypto_sign_PUBLICKEYBYTES];
unsigned char rx[crypto_kx_SESSIONKEYBYTES];
unsigned char tx[crypto_kx_SESSIONKEYBYTES];
unsigned char dev_public_key[crypto_box_PUBLICKEYBYTES] = {
    0xbd, 0xcc, 0xd0, 0x68, 0xf1, 0x47, 0x36, 0x4f,
    0xcd, 0x39, 0x7a, 0x7a, 0x2c, 0x54, 0xb2, 0xc2,
    0x51, 0xc3, 0xf0, 0xa4, 0x53, 0xa4, 0x5a, 0x08,
    0x02, 0xc7, 0x06, 0xd8, 0x98, 0x62, 0x07, 0x6f
};

const unsigned char dev_secret_key[crypto_box_SECRETKEYBYTES] = {
    0xd1, 0x2c, 0x26, 0x1e, 0x11, 0xed, 0x5d, 0xe4,
    0x10, 0x5e, 0x59, 0xf9, 0x7b, 0x7d, 0xc5, 0x09,
    0xa2, 0xb0, 0x93, 0x22, 0x32, 0xc6, 0x45, 0x07,
    0xea, 0x18, 0xd5, 0xc9, 0xe7, 0xbe, 0x86, 0xfe
};

unsigned char Ack[8] = {
  0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
};

// Wrapper function for crypto_kx_server_session_keys
int generate_session_keys() {
    if (crypto_kx_client_session_keys(rx, tx, server_pk, server_sk, client_pk) != 0) {
        return 1;
    }
    return 0;
}

// Initiates Sodium and generates vSIM keypair.
int init(){
    magic_random_init();
    randombytes_set_implementation(&randombytes_salsa20_implementation);
    
    if (sodium_init() < 0) {
        EAPP_RETURN(1);
    }

    if (crypto_kx_keypair(server_pk, server_sk) != 0) {
        EAPP_RETURN(1);
    }
    if (crypto_sign_keypair(server_spk, server_ssk) != 0){
      EAPP_RETURN(1);
    }
}

void channel_box(unsigned char* msg, size_t len, unsigned char* buffer, unsigned char* key){
  /* We store the nonce at the end of the ciphertext buffer for easy
     access */
  size_t buf_padded_len;

  memcpy(buffer, msg, len);

  if (sodium_pad(&buf_padded_len, buffer, len, MSG_BLOCKSIZE, BLOCK_UP(len)) != 0) {
    ocall_print_string("[C] Unable to pad message, exiting\n");
    EAPP_RETURN(1);
  }

  unsigned char* nonceptr = &(buffer[crypto_secretbox_MACBYTES+buf_padded_len]);
  randombytes_buf(nonceptr, crypto_secretbox_NONCEBYTES);


  if(crypto_secretbox_easy(buffer, buffer, buf_padded_len, nonceptr, key) != 0){
    ocall_print_string("[C] Unable to encrypt message, exiting\n");
    EAPP_RETURN(1);
  }
  
  ocall_print_string("[C] Successfully Encrypted\n");
}

void channel_unbox(unsigned char* msg_buffer, size_t len, size_t* datalen){
  /* We store the nonce at the end of the ciphertext buffer for easy
     access */
  size_t clen = len - crypto_secretbox_NONCEBYTES;
  unsigned char* nonceptr = &(msg_buffer[clen]);

  ocall_print_string("DDD");
  if (crypto_secretbox_open_easy(msg_buffer, msg_buffer, clen, nonceptr, rx) != 0){
    ocall_print_string("[C] Invalid message, ignoring\n");
    return -1;
  }
  size_t ptlen = 32;

  size_t unpad_len;
  if( sodium_unpad(&unpad_len, msg_buffer, ptlen, MSG_BLOCKSIZE) != 0){
    ocall_print_string("[C] Invalid message padding, ignoring\n");
    return -1;
  }
  
  *datalen = unpad_len;

  ocall_print_string("[C] Successfully Decrypted\n");
  return 0;
                    }

void asymmetric_box(unsigned char* msg, size_t len, unsigned char* buffer, unsigned char* key){
  size_t encrypted_len = len + crypto_box_SEALBYTES;

  ocall_print_string("Provider Pub key: \n");
    const char hex_chars[] = "0123456789abcdef";
    char hex_string[crypto_secretbox_NONCEBYTES*2 + 1];

    for (size_t i = 0; i < crypto_secretbox_NONCEBYTES; i++) {
        hex_string[i * 2] = hex_chars[(key[i] >> 4) & 0xF];
        hex_string[i * 2 + 1] = hex_chars[key[i] & 0xF];
    }
    hex_string[crypto_secretbox_NONCEBYTES*2] = '\0';  

    ocall_print_string(hex_string);
    
    // Encrypt using the public key
    if (crypto_box_seal(buffer, msg, len, key) != 0) {
        ocall_print_string("[C] Unable to encrypt message, exiting\n");
        EAPP_RETURN(1);
    }
    
    ocall_print_string("[C] Successfully Encrypted\n");
}

void asymmetric_unbox(unsigned char* encrypted_data, 
                    size_t encrypted_len,
                    unsigned char* decrypted_data){

    if (crypto_box_seal_open(
            decrypted_data,              /* destination for decrypted message */
            encrypted_data,              /* source ciphertext */
            encrypted_len,               /* length of ciphertext */
            dev_public_key,           /* dev public key */
            dev_secret_key           /* dev secret key */
        ) != 0){
          ocall_print_string("[C] Unable to decrypt message, exiting\n");
          EAPP_RETURN(1);
        }

    ocall_print_string("[C] Successfully Decrypted\n");    

}
