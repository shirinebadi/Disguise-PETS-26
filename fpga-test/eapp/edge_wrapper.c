#include "eapp_utils.h"
#include "string.h"
#include "syscall.h"
#include "edge_wrapper.h"



void edge_init(){
  /* Nothing for now, will probably register buffers/callsites
     later */
}

void ocall_wait_for_message(struct edge_data *msg){
  ocall(OCALL_WAIT_FOR_MESSAGE, NULL, 0, msg, sizeof(struct edge_data));
  return;
}
void ocall_wait_for_challenge(struct edge_data *msg){
  ocall(OCALL_WAIT_FOR_CHALLENGE, NULL, 0, msg, sizeof(struct edge_data));
  return;
}
unsigned long ocall_print_string(char* string){
  unsigned long retval;
  ocall(OCALL_PRINT_STRING, string, strlen(string)+1, &retval ,sizeof(unsigned long));
  return retval;
}
void ocall_send_ra_req(char* buffer, size_t len){
  
  ocall(OCALL_SEND_RA_REQ, buffer, len, 0, 0);

  return; 
}

void ocall_send_buffer(char* buffer, size_t len){
  
  ocall(OCALL_SEND_BUFFER, buffer, len, 0, 0);

  return; 
}

void ocall_wait_for_ra_resp(struct edge_data *msg){
  ocall(OCALL_WAIT_FOR_RESP, NULL, 0, msg, sizeof(struct edge_data));
  return;
}

void ocall_send_challenge_response(char* buffer, size_t len){
  ocall(OCALL_SEND_CHALLENGE_RESPONSE, buffer, len, 0, 0);
  
  return;
}
