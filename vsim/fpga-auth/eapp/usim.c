#include <stdint.h>
#include "usim.h"
#include "eapp_utils.h"
#include "string.h"
#include "aes.h"

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

LIBLTE_ERROR_ENUM
liblte_security_milenage_f2345(unsigned char* k, unsigned char* op_c, unsigned char* rand, unsigned char* res, unsigned char* ck, unsigned char* ik, unsigned char* ak)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
  unsigned int            i;
  unsigned char             temp[16];
  unsigned char             out[16];
  unsigned char             input[16];
unsigned long long clen;

  if (k != NULL && op_c != NULL && rand != NULL && res != NULL && ck != NULL && ik != NULL && ak != NULL) {
    // Compute temp
    struct AES_ctx ctx;
    
    // Initialize the context with key
    // For AES-128, use AES_init_ctx
    // For AES-192/256, use AES_init_ctx_iv but set iv to NULL
    AES_init_ctx(&ctx, k);
    for (i = 0; i < 16; i++) {
      input[i] = rand[i] ^ op_c[i];
    }
    //ocall_print_string("Context!");
    memcpy(temp, input, 16);
    AES_ECB_encrypt(&ctx, temp);
    //Compute out for RES and AK
    for (i = 0; i < 16; i++) {
      input[i] = temp[i] ^ op_c[i];
    }
    input[15] ^= 1;
    memcpy(out, input, 16);
    AES_ECB_encrypt(&ctx, out);
    for (i = 0; i < 16; i++) {
      out[i] ^= op_c[i];
    }

    // Return RES
    for (i = 0; i < 8; i++) {
      res[i] = out[i + 8];
    }

    // Return AK
    for (i = 0; i < 6; i++) {
      ak[i] = out[i];
    }
    //print_h(ak,8);
    // Compute out for CK
    for (i = 0; i < 16; i++) {
      input[(i + 12) % 16] = temp[i] ^ op_c[i];
    }
    input[15] ^= 2;
    memcpy(out, input, 16);
    AES_ECB_encrypt(&ctx, out);
    for (i = 0; i < 16; i++) {
      out[i] ^= op_c[i];
    }

    // Return CK
    for (i = 0; i < 16; i++) {
      ck[i] = out[i];
    }
    //print_h(ck,16);

    // Compute out for IK
    for (i = 0; i < 16; i++) {
      input[(i + 8) % 16] = temp[i] ^ op_c[i];
    }
    input[15] ^= 4;
            memcpy(out, input, 16);
        AES_ECB_encrypt(&ctx, out);
    for (i = 0; i < 16; i++) {
      out[i] ^= op_c[i];
    }

    // Return IK
    for (i = 0; i < 16; i++) {
      ik[i] = out[i];
    }

    err = LIBLTE_SUCCESS;
  }

  return (err);
}

LIBLTE_ERROR_ENUM 
liblte_security_milenage_f1(unsigned char* k, 
                                             unsigned char* op_c, 
                                             unsigned char* rand, 
                                             unsigned char* sqn, 
                                             unsigned char* amf, 
                                             unsigned char* mac_a)
{
    LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
    struct AES_ctx ctx;
    unsigned char temp[16];
    unsigned char in1[16];
    unsigned char out1[16];
    unsigned char input[16];

    if (k != NULL && op_c != NULL && rand != NULL && 
        sqn != NULL && amf != NULL && mac_a != NULL) {
        
        // Initialize AES context with key
        AES_init_ctx(&ctx, k);

        // Compute temp: temp = AES(rand ⊕ op_c)
        for (int i = 0; i < 16; i++) {
            input[i] = rand[i] ^ op_c[i];
        }
        AES_ECB_encrypt(&ctx, input);
        memcpy(temp, input, 16);

        // Construct in1: [sqn||amf||sqn||amf]
        for (int i = 0; i < 6; i++) {
            in1[i] = sqn[i];
            in1[i + 8] = sqn[i];
        }
        for (int i = 0; i < 2; i++) {
            in1[i + 6] = amf[i];
            in1[i + 14] = amf[i];
        }

        // Compute out1: out1 = AES((in1 ⊕ op_c) ⊕ temp) ⊕ op_c
        for (int i = 0; i < 16; i++) {
            input[(i + 8) % 16] = in1[i] ^ op_c[i];
        }
        for (int i = 0; i < 16; i++) {
            input[i] ^= temp[i];
        }
        AES_ECB_encrypt(&ctx, input);
        for (int i = 0; i < 16; i++) {
            input[i] ^= op_c[i];
        }
        memcpy(out1, input, 16);

        // Set MAC-A to first 8 bytes of out1
        memcpy(mac_a, out1, 8);

        err = LIBLTE_SUCCESS;
    }

    return err;
}

LIBLTE_ERROR_ENUM gen_auth_res_milenage(unsigned char* opc, unsigned char* rand, unsigned char* autn_enb, unsigned char* res, int* res_len, unsigned char* ak_xor_sqn)
{
  LIBLTE_ERROR_ENUM err = LIBLTE_ERROR_INVALID_INPUTS;
  uint32_t      i;
  unsigned char       sqn[6];
  unsigned char amf[4];
  unsigned char ak[6];
  unsigned char mac[8];
  unsigned char autn[16];
  // This should be stored in the secure storage
  unsigned char k[]    = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

  // Use RAND and K to compute RES, CK, IK and AK
  liblte_security_milenage_f2345(k, opc, rand, res, ck, ik, ak);

  // Extract sqn from autn
  for (i = 0; i < 6; i++) {
    sqn[i] = autn_enb[i] ^ ak[i];
  }
  // Extract AMF from autn
  for (int i = 0; i < 2; i++) {
    amf[i] = autn_enb[6 + i];
  }

  // Generate MAC
  liblte_security_milenage_f1(k, opc, rand, sqn, amf, mac);

  // Construct AUTN
  for (i = 0; i < 6; i++) {
    autn[i] = sqn[i] ^ ak[i];
  }
  for (i = 0; i < 2; i++) {
    autn[6 + i] = amf[i];
  }
  for (i = 0; i < 8; i++) {
    autn[8 + i] = mac[i];
  }

  // Compare AUTNs
  // for (i = 0; i < 16; i++) {
  //   if (autn[i] != autn_enb[i]) {
  //     //err = LIBLTE_ERROR_ENCODE_FAIL
  //   }
  // }
  // print_hex(k, 16);
  // print_hex(res, 8);
  // print_hex(ck, 16);
  // print_hex(ik,16);
  // print_hex(ak,6);
  // print_h(autn, 16);
  // print_hex(mac, 8);

  for (i = 0; i < 6; i++) {
    ak_xor_sqn[i] = sqn[i] ^ ak[i];
  }

  err = LIBLTE_SUCCESS;
  return err;
}
