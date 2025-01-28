#ifndef _EDGE_WRAPPER_H_
#define _EDGE_WRAPPER_H_

#include "edge_call.h"

#define OCALL_PRINT_STRING 1
#define OCALL_WAIT_FOR_MESSAGE 2
#define OCALL_SEND_RA_REQ 3
#define OCALL_WAIT_FOR_RESP 4
#define OCALL_SEND_BUFFER 5


void edge_init();
unsigned long ocall_print_string(char* string);
// void ocall_wait_for_message(struct edge_data *msg);
// void ocall_send_ra_req(char* buffer, size_t len);
// void ocall_wait_for_ra_resp(struct edge_data *msg);
// void ocall_send_buffer(char* buffer, size_t len);

#endif /* _EDGE_WRAPPER_H_ */

