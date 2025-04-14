#ifndef _USIM_H_
#define _USIM_H_

#include <stdint.h>
#include "eapp_utils.h"
#include "string.h"

extern unsigned char ck[16];
extern unsigned char ik[16];

typedef enum {
  LIBLTE_SUCCESS = 0,
  LIBLTE_ERROR_INVALID_INPUTS,
  LIBLTE_ERROR_ENCODE_FAIL,
  LIBLTE_ERROR_DECODE_FAIL,
  LIBLTE_ERROR_INVALID_CRC,
  LIBLTE_ERROR_N_ITEMS
} LIBLTE_ERROR_ENUM;

LIBLTE_ERROR_ENUM
liblte_security_milenage_f2345(unsigned char* k, unsigned char* op_c, unsigned char* rand, unsigned char* res, unsigned char* ck, unsigned char* ik, unsigned char* ak);
LIBLTE_ERROR_ENUM 
gen_auth_res_milenage(unsigned char* opc, unsigned char* rand, unsigned char* autn_enb, unsigned char* res, int* res_len, unsigned char* ak_xor_sqn);
LIBLTE_ERROR_ENUM 
liblte_security_milenage_f1(unsigned char* k, 
                                             unsigned char* op_c, 
                                             unsigned char* rand, 
                                             unsigned char* sqn, 
                                             unsigned char* amf, 
                                             unsigned char* mac_a);

#endif /* _EDGE_WRAPPER_H_ */