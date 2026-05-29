#include "edge_wrapper.h"
#include <string.h>

// Register functions
#define OCALL_PRINT_STRING 1
#define OCALL_WAIT_FOR_MESSAGE 2
#define OCALL_SEND_RA_REQ 3
#define OCALL_WAIT_FOR_RESP 4
#define OCALL_SEND_BUFFER 5
#define OCALL_WAIT_FOR_CHALLENGE 6
#define OCALL_SEND_CHALLENGE_RESPONSE 7

void
edge_init(Keystone::Enclave* enclave) {
  enclave->registerOcallDispatch(incoming_call_dispatch);

  register_call(OCALL_PRINT_STRING, print_string_wrapper);
  register_call(OCALL_WAIT_FOR_CHALLENGE, wait_for_challenge_wrapper);
  register_call(OCALL_SEND_CHALLENGE_RESPONSE, send_challenge_response_wrapper);
  edge_call_init_internals(
      (uintptr_t)enclave->getSharedBuffer(), enclave->getSharedBufferSize());
}

void
print_string_wrapper(void* buffer) {
  /* Parse and validate the incoming call data */
  struct edge_call* edge_call = (struct edge_call*)buffer;
  uintptr_t call_args;
  unsigned long ret_val;
  size_t arg_len;
  if (edge_call_args_ptr(edge_call, &call_args, &arg_len) != 0) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return;
  }

  /* Pass the arguments from the eapp to the exported ocall function */
  print_string((char*)call_args);

  /* Setup return data from the ocall function */
  uintptr_t data_section = edge_call_data_ptr();
  memcpy((void*)data_section, &ret_val, sizeof(unsigned long));
  if (edge_call_setup_ret(
          edge_call, (void*)data_section, sizeof(unsigned long))) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
  } else {
    edge_call->return_data.call_status = CALL_STATUS_OK;
  }

  /* This will now eventually return control to the enclave */
  return;
}

void wait_for_challenge_wrapper(void* buffer)
{
  struct edge_call* edge_call = (struct edge_call*)buffer;

  uintptr_t call_args;
  unsigned long ret_val;
  size_t args_len;
  if(edge_call_args_ptr(edge_call, &call_args, &args_len) != 0){
    edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return;
  }

  encl_message_t host_msg = send_challenge_to_vSIM();

  // This handles wrapping the data into an edge_data_t and storing it
  // in the shared region.
  if( edge_call_setup_wrapped_ret(edge_call, host_msg.host_ptr, host_msg.len)){
    edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
  }
  else{
    edge_call->return_data.call_status = CALL_STATUS_OK;
  }

  return;
}

void
send_challenge_response_wrapper(void* buffer)
{
  struct edge_call* edge_call = (struct edge_call*)buffer;

  uintptr_t call_args;
  unsigned long ret_val;
  size_t args_len;
  if(edge_call_args_ptr(edge_call, &call_args, &args_len) != 0){
    edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return;
  }

  send_challenge_response((void*)call_args, edge_call->call_arg_size);
  edge_call->return_data.call_status = CALL_STATUS_OK;

  return;
}
