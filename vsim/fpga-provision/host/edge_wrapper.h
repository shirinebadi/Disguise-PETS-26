#ifndef _EDGE_WRAPPER_H_
#define _EDGE_WRAPPER_H_

#include <edge_call.h>
#include "keystone.h"

typedef unsigned char byte;
typedef struct encl_message_t {
  void* host_ptr;
  size_t len;
} encl_message_t;


void edge_init(Keystone::Enclave* enclave);
void wait(void* buffer);


void print_string_wrapper(void* buffer);
unsigned long print_string(char* str);

void wait_for_message_wrapper(void* buffer);
encl_message_t wait_for_message();

void send_ra_req_wrapper(void* buffer);
void send_ra_req(void* data, size_t len);

void wait_for_resp_wrapper(void* buffer);
encl_message_t wait_for_resp();

void send_buffer_wrapper(void* buffer);
void send_buffer(void* data, size_t len);

void wait_for_challenge_wrapper(void* buffer);
encl_message_t send_challenge_to_vSIM();

void send_challenge_response(void* data, size_t len);
void
send_challenge_response_wrapper(void* buffer);

#endif /* _EDGE_WRAPPER_H_ */
