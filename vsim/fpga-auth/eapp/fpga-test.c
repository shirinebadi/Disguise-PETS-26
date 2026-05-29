#include "app/eapp_utils.h"
#include "string.h"
#include "syscall.h"
#include "malloc.h"
#include "sodium.h"
#include "hacks.h"
#include <time.h>
#include <sys/time.h>
#include "edge_wrapper.h"
#include "usim.h"

unsigned char ck[16];
unsigned char ik[16];
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


void ltoa(long num, char* str) {
  int i = 0;
  int is_negative = 0;
  
  if (num < 0) {
      is_negative = 1;
      num = -num;
  }
  
  if (num == 0) {
      str[i++] = '0';
      str[i] = '\0';
      return;
  }
  
  while (num != 0) {
      str[i++] = (num % 10) + '0';
      num = num / 10;
  }
  
  if (is_negative) {
      str[i++] = '-';
  }
  
  str[i] = '\0';
  
  int start = 0;
  int end = i - 1;
  while (start < end) {
      char temp = str[start];
      str[start] = str[end];
      str[end] = temp;
      start++;
      end--;
  }
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
  //ocall_print_string("------------autnenb:\n");
  //print_hex(autn_enb, 16);
  struct timeval delay_start, delay_end;
  
  gettimeofday(&delay_start, NULL);
  
    if (gen_auth_res_milenage(opc_o, rand, autn_enb, res_o, 8, ak_xor_sqn) != 0){
      ocall_print_string("Error in f2345");
    }
    gettimeofday(&delay_end, NULL);
  
    long seconds = delay_end.tv_sec - delay_start.tv_sec;
    long microseconds = delay_end.tv_usec - delay_start.tv_usec;
    
    if (microseconds < 0) {
        seconds--;
        microseconds += 1000000;
    }
    
    long milliseconds = (seconds * 1000) + (microseconds / 1000);
    
    char debug[100];
    ltoa(seconds, debug);
    ocall_print_string("Seconds: ");
    ocall_print_string(debug);
    ocall_print_string("\n");
    ltoa(microseconds, debug);
    ocall_print_string("Microseconds: ");
    ocall_print_string(debug);
    ocall_print_string("\n");
    ltoa(milliseconds, debug);
    ocall_print_string("MilliSecond: ");
    ocall_print_string(debug);
    ocall_print_string("\n");


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