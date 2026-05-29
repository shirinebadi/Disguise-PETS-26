#include "edge_wrapper.h"
#include <string.h>
#include <chrono>
#include <thread>

// Register functions
#define OCALL_PRINT_STRING 1
#define OCALL_WAIT_FOR_MESSAGE 2
#define OCALL_SEND_RA_REQ 3
#define OCALL_WAIT_FOR_RESP 4
#define OCALL_SEND_BUFFER 5
#define OCALL_WAIT 8

void
edge_init(Keystone::Enclave* enclave) {
  enclave->registerOcallDispatch(incoming_call_dispatch);

  register_call(OCALL_PRINT_STRING, print_string_wrapper);
  register_call(OCALL_WAIT_FOR_MESSAGE, wait_for_message_wrapper);
  register_call(OCALL_SEND_RA_REQ, send_ra_req_wrapper);
  register_call(OCALL_WAIT_FOR_RESP, wait_for_resp_wrapper);
  register_call(OCALL_SEND_BUFFER, send_buffer_wrapper);
  register_call(OCALL_WAIT, wait);
  edge_call_init_internals(
      (uintptr_t)enclave->getSharedBuffer(), enclave->getSharedBufferSize());
}

void wait(void* buffer) {
  struct edge_call* edge_call = (struct edge_call*)buffer;

  uintptr_t call_args;
  unsigned long ret_val;
  size_t args_len;
  if(edge_call_args_ptr(edge_call, &call_args, &args_len) != 0){
    edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return;
  }

  std::this_thread::sleep_for(std::chrono::milliseconds(2000));


  edge_call->return_data.call_status = CALL_STATUS_OK;
  return;

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

void wait_for_message_wrapper(void* buffer)
{

  /* For now we assume the call struct is at the front of the shared
   * buffer. This will have to change to allow nested calls. */
  struct edge_call* edge_call = (struct edge_call*)buffer;

  uintptr_t call_args;
  unsigned long ret_val;
  size_t args_len;
  if(edge_call_args_ptr(edge_call, &call_args, &args_len) != 0){
    edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return;
  }

  encl_message_t host_msg = wait_for_message();

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
send_ra_req_wrapper(void* buffer)
{
  struct edge_call* edge_call = (struct edge_call*)buffer;

  uintptr_t call_args;
  unsigned long ret_val;
  size_t args_len;
  if(edge_call_args_ptr(edge_call, &call_args, &args_len) != 0){
    edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return;
  }

  send_ra_req((void*)call_args, edge_call->call_arg_size);
  edge_call->return_data.call_status = CALL_STATUS_OK;

  return;

}

void
send_buffer_wrapper(void* buffer)
{
  struct edge_call* edge_call = (struct edge_call*)buffer;

  uintptr_t call_args;
  unsigned long ret_val;
  size_t args_len;
  if(edge_call_args_ptr(edge_call, &call_args, &args_len) != 0){
    edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return;
  }

  send_buffer((void*)call_args, edge_call->call_arg_size);
  edge_call->return_data.call_status = CALL_STATUS_OK;

  return;
}

void 
wait_for_resp_wrapper(void* buffer){
  struct edge_call* edge_call = (struct edge_call*)buffer;
  printf("Recieved!");
  uintptr_t call_args;
  unsigned long ret_val;
  size_t args_len;
  if(edge_call_args_ptr(edge_call, &call_args, &args_len) != 0){
    edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return;
  }
  printf("Recieved!");
  encl_message_t server_msg = wait_for_resp();
  printf("Recieved!");

  if( edge_call_setup_wrapped_ret(edge_call, server_msg.host_ptr, server_msg.len)){
    edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
  }
  else{
    edge_call->return_data.call_status = CALL_STATUS_OK;
  }

  return;

}
