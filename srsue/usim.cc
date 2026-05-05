/**
 * Copyright 2013-2023 Software Radio Systems Limited
 *
 * This file is part of srsRAN.
 *
 * srsRAN is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * srsRAN is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * A copy of the GNU Affero General Public License can be found in
 * the LICENSE file in the top-level directory of this distribution
 * and at http://www.gnu.org/licenses/.
 *
 */

#include "srsue/hdr/stack/upper/usim.h"
#include "srsran/common/bcd_helpers.h"
#include "srsran/common/standard_streams.h"
#include <cstdio>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <array>
#include <sstream>
#include <stdio.h>
#include <atomic>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <unistd.h>
#include <sys/time.h>

using namespace srsran;

namespace srsue {

bool usim::fpga_initialized = false;
usim::usim(srslog::basic_logger& logger) : usim_base(logger) {}

long usim::get_time_diff_ms(struct timeval start, struct timeval end) {
    long seconds = end.tv_sec - start.tv_sec;
    long microseconds = end.tv_usec - start.tv_usec;
    
    // Adjust for microsecond overflow
    if (microseconds < 0) {
        seconds--;
        microseconds += 1000000;
    }
    
    // Convert to milliseconds
    return (seconds * 1000) + (microseconds / 1000);
}


int usim::init(usim_args_t* args)
{
  imsi_str = args->imsi;
  imei_str = args->imei;
  const char* SHARED_MEM_NAME = "/test_shared_memory";
  shared_mem_fd = shm_open(SHARED_MEM_NAME, O_RDWR, 0666);
   // if (shared_mem_fd == -1) {
   //     perror("Error opening shared memory");
   //     return 1;
    //}

    shared_data = (struct SharedData*)mmap(
        NULL, sizeof(struct SharedData), PROT_READ | PROT_WRITE, MAP_SHARED, shared_mem_fd, 0);
    
    //if (shared_data == MAP_FAILED) {
    //logger.error("Error mapping shared memory: %s", strerror(errno));
   // close(shared_mem_fd);
    //shared_mem_fd = -1;
   // return 0;
    //}
    
     logger.info("Shared memory for vSIM initialized successfully");


  const char* imsi_c = args->imsi.c_str();
  const char* imei_c = args->imei.c_str();

  auth_algo = auth_algo_milenage;
  if ("xor" == args->algo) {
    auth_algo = auth_algo_xor;
  }

  if (32 == args->k.length()) {
    str_to_hex(args->k, k);
  } else {
    logger.error("Invalid length for K: %zu should be %d", args->k.length(), 32);
    srsran::console("Invalid length for K: %zu should be %d\n", args->k.length(), 32);
  }

  if (auth_algo == auth_algo_milenage) {
    if (args->using_op) {
      if (32 == args->op.length()) {
        str_to_hex(args->op, op);
        compute_opc(k, op, opc);
      } else {
        logger.error("Invalid length for OP: %zu should be %d", args->op.length(), 32);
        srsran::console("Invalid length for OP: %zu should be %d\n", args->op.length(), 32);
      }
    } else {
      if (32 == args->opc.length()) {
        str_to_hex(args->opc, opc);
      } else {
        logger.error("Invalid length for OPc: %zu should be %d", args->opc.length(), 32);
        srsran::console("Invalid length for OPc: %zu should be %d\n", args->opc.length(), 32);
      }
    }
  }

  if (15 == args->imsi.length()) {
    imsi = 0;
    for (int i = 0; i < 15; i++) {
      imsi *= 10;
      imsi += imsi_c[i] - '0';
    }
  } else {
    logger.error("Invalid length for IMSI: %zu should be %d", args->imsi.length(), 15);
    srsran::console("Invalid length for IMSI: %zu should be %d\n", args->imsi.length(), 15);
  }

  if (15 == args->imei.length()) {
    imei = 0;
    for (int i = 0; i < 15; i++) {
      imei *= 10;
      imei += imei_c[i] - '0';
    }
  } else {
    logger.error("Invalid length for IMEI: %zu should be %d", args->imei.length(), 15);
    srsran::console("Invalid length for IMEI: %zu should be %d\n", args->imei.length(), 15);
  }

  initiated = true;

  return SRSRAN_SUCCESS;
}

void usim::stop() {}

/*******************************************************************************
  NAS interface
*******************************************************************************/

auth_result_t usim::generate_authentication_response(uint8_t* rand,
                                                     uint8_t* autn_enb,
                                                     uint16_t mcc,
                                                     uint16_t mnc,
                                                     uint8_t* res,
                                                     int*     res_len,
                                                     uint8_t* k_asme_)
{
  auth_result_t auth_result;
  uint8_t       ak_xor_sqn[6];

  if (auth_algo_xor == auth_algo) {
    auth_result = gen_auth_res_xor(rand, autn_enb, res, res_len, ak_xor_sqn);
  } else {
    auth_result = gen_auth_res_milenage(rand, autn_enb, res, res_len, ak_xor_sqn);
  }

  if (auth_result == AUTH_OK) {
    // Generate K_asme
    security_generate_k_asme(ck, ik, ak_xor_sqn, mcc, mnc, k_asme_);
  }
  return auth_result;
}

auth_result_t usim::generate_authentication_response_5g(uint8_t*    rand,
                                                        uint8_t*    autn_enb,
                                                        const char* serving_network_name,
                                                        uint8_t*    abba,
                                                        uint32_t    abba_len,
                                                        uint8_t*    res_star,
                                                        uint8_t*    k_amf)
{
  auth_result_t auth_result;
  uint8_t       ak_xor_sqn[6];
  uint8_t       res[16];
  uint8_t       k_ausf[32];
  uint8_t       k_seaf[32];
  int           res_len;
  struct timeval start_time, end_time;
  long time_diff_ms;
  std::string res_star_str, k_ausf_str, k_seaf_str, k_amf_str;

  if (auth_algo_xor == auth_algo) {
    auth_result = gen_auth_res_xor(rand, autn_enb, res, &res_len, ak_xor_sqn);
  } else {
  // Check if USE_VSIM environment variable is set to "true"
  const char* use_vsim_env = getenv("USE_VSIM");
  
  if (use_vsim_env != nullptr && strcmp(use_vsim_env, "true") == 0) {
    logger.debug("Using vSIM for authentication (via Keystone TEE)");
    gettimeofday(&start_time, NULL);
    auth_result = gen_auth_res_milenage_vsim(rand, autn_enb, res, &res_len, ak_xor_sqn);
    gettimeofday(&end_time, NULL);
    time_diff_ms = get_time_diff_ms(start_time, end_time);
      
    logger.info("vSIM 5G authentication time: %ld ms", time_diff_ms);
  } else {
    logger.debug("Using standard milenage for authentication");
    gettimeofday(&start_time, NULL);
    auth_result = gen_auth_res_milenage(rand, autn_enb, res, &res_len, ak_xor_sqn);
    gettimeofday(&end_time, NULL);
    time_diff_ms = get_time_diff_ms(start_time, end_time);
      
    logger.info("Standard milenage 5G authentication time: %ld ms", time_diff_ms);
  }
}

  if (auth_result == AUTH_OK) {
    // Generate RES STAR
    security_generate_res_star(ck, ik, serving_network_name, rand, res, res_len, res_star);
    logger.debug(res_star, 16, "RES STAR");

    // Generate K_ausf
    security_generate_k_ausf(ck, ik, ak_xor_sqn, serving_network_name, k_ausf);
    logger.debug(k_ausf, 32, "K AUSF");

    // Generate K_seaf
    security_generate_k_seaf(k_ausf, serving_network_name, k_seaf);
    logger.debug(k_seaf, 32, "K SEAF");

    // Generate K_amf
    logger.debug(abba, abba_len, "ABBA:");
    logger.debug("IMSI: %s", imsi_str.c_str());
    security_generate_k_amf(k_seaf, imsi_str.c_str(), abba, abba_len, k_amf);
    logger.debug(k_amf, 32, "K AMF");

  }
  return auth_result;
}

/*******************************************************************************
  Helpers
*******************************************************************************/
std::string usim::exec(const char* cmd) {
    std::array<char, 128> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    if (!pipe) {
        throw std::runtime_error("popen() failed!");
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return result;
}

std::string usim::extract_value(const std::string& output, const std::string& label) {
    std::istringstream stream(output);
    std::string line;
    while (std::getline(stream, line)) {
        if (line.find(label + ": ") != std::string::npos) {
            return line.substr(line.find(": ") + 2);
        }
    }
    return "";
}

auth_result_t
usim::gen_auth_res_milenage_vsim(uint8_t* rand, uint8_t* autn_enb, uint8_t* res, int* res_len, uint8_t* ak_xor_sqn)
{
auth_result_t result = AUTH_OK;
std::string autn_str, autn_enb_str, k_str, opc_str, rand_str, res_str, ck_str, ik_str, ak_str, xor_str;
for(int i = 0; i < 16; i++) {
    char temp[3];
    snprintf(temp, sizeof(temp), "%02x", (unsigned int)opc[i]);
    opc_str += temp;
}
logger.debug("OPC (hex): %s", opc_str.c_str());

for(int i = 0; i < 16; i++) {
    char temp[3];
    snprintf(temp, sizeof(temp), "%02x", (unsigned int)rand[i]);
    rand_str += temp;
}
logger.debug("RAND (hex): %s", rand_str.c_str());

for(int i = 0; i < 16; i++) {
    char temp[3];
    snprintf(temp, sizeof(temp), "%02x", (unsigned int)autn_enb[i]);
    autn_enb_str += temp;
}
logger.debug("autn_enb_str (hex): %s", autn_enb_str.c_str());

if (!fpga_initialized) {
logger.debug("Calling vSIM (for fpga) with rand, autn, and opc");
//std::string cmd = "/usr/share/keystone/examples/fpga-test.ke " + rand_str + " " + opc_str + " "+ autn_enb_str;
 const char* SHARED_MEM_NAME = "/test_shared_memory";

 try {
 
    if (shared_data == nullptr || shared_data == MAP_FAILED) {
        logger.error("Shared memory not initialized");
        return AUTH_FAILED;
      }
    
    // Clear any previous authentication data
    
    
    // Write authentication data to shared memory
    memcpy(shared_data->auth_data.rand_bytes, rand, 16);
    memcpy(shared_data->auth_data.opc_bytes, opc, 16);
    memcpy(shared_data->auth_data.autenb_bytes, autn_enb, 16);
    
    // Set command type and ready flag
    shared_data->command_type = CMD_AUTHENTICATE;
    shared_data->command_ready.store(true, std::memory_order_release);
    
    logger.debug("Authentication request written to shared memory (Checking w/ atomic)");
    *res_len = 8;
    
    const int TIMEOUT_SECONDS = 5;
    int wait_time = 0;
    while (!(shared_data->auth_response_ready.load(std::memory_order_acquire)) && (wait_time < TIMEOUT_SECONDS)) {
        usleep(400000); 
        wait_time++;
        logger.debug("Waiting...");
    }
    
    // std::atomic_thread_fence(std::memory_order_acquire);

    for(int i = 0; i < 6; i++) {
    char temp[3];
    snprintf(temp, sizeof(temp), "%02x", (unsigned int)shared_data->ak_xor_sqn[i]);
    xor_str += temp;
}
    logger.debug("ak_xor_sqn (hex): %s", xor_str.c_str());
    memcpy(res, shared_data->res, 8);
    memcpy(ak_xor_sqn, shared_data->ak_xor_sqn, 6);
    memcpy(ck, shared_data->ck, 16);
    memcpy(ik, shared_data->ik, 16);	
      for(int i = 0; i < 8; i++) {
    char temp[3];
    snprintf(temp, sizeof(temp), "%02x", (unsigned int)res[i]);
    res_str += temp;
}
logger.debug("res (hex): %s", res_str.c_str());


 fpga_initialized = true;
    
 } catch (const std::exception& e) {
            logger.error("Exception in FPGA authentication: %s", e.what());
            return AUTH_FAILED;
        }
 }else{
 logger.debug("Using cached vSIM results from previous initialization");
  gen_auth_res_milenage(rand, autn_enb, res, res_len, ak_xor_sqn);
 }


 return result;
    

}


auth_result_t
usim::gen_auth_res_milenage(uint8_t* rand, uint8_t* autn_enb, uint8_t* res, int* res_len, uint8_t* ak_xor_sqn)
{
  auth_result_t result = AUTH_OK;
  uint32_t      i;
  uint8_t       sqn[6];
  std::string autn_str, autn_enb_str, k_str, opc_str, rand_str, res_str, ck_str, ik_str, ak_str, ak_xor_sqn_str;

  // Use RAND and K to compute RES, CK, IK and AK
  security_milenage_f2345(k, opc, rand, res, ck, ik, ak);
  logger.debug("Sent challenge:");

for(int i = 0; i < 16; i++) {
    char temp[3];
    snprintf(temp, sizeof(temp), "%02x", (unsigned int)k[i]);
    k_str += temp;
}
logger.debug("K (hex): %s", k_str.c_str());

for(int i = 0; i < 16; i++) {
    char temp[3];
    snprintf(temp, sizeof(temp), "%02x", (unsigned int)opc[i]);
    opc_str += temp;
}
logger.debug("OPC (hex): %s", opc_str.c_str());

for(int i = 0; i < 16; i++) {
    char temp[3];
    snprintf(temp, sizeof(temp), "%02x", (unsigned int)rand[i]);
    rand_str += temp;
}
logger.debug("RAND (hex): %s", rand_str.c_str());

for(int i = 0; i < AK_LEN; i++) {
    char temp[3];
    snprintf(temp, sizeof(temp), "%02x", (unsigned int)ak[i]);
    ak_str += temp;
}
logger.debug("AK (hex): %s", ak_str.c_str());

for(int i = 0; i < CK_LEN; i++) {
    char temp[3];
    snprintf(temp, sizeof(temp), "%02x", (unsigned int)ck[i]);
    ck_str += temp;
}
logger.debug("CK (hex): %s", ck_str.c_str());
for(int i = 0; i < IK_LEN; i++) {
    char temp[3];
    snprintf(temp, sizeof(temp), "%02x", (unsigned int)ik[i]);
    ik_str += temp;
}
logger.debug("CK (hex): %s", ik_str.c_str());
for(int i = 0; i < 8; i++) {
    char temp[3];
    snprintf(temp, sizeof(temp), "%02x", (unsigned int)res[i]);
    res_str += temp;
}
logger.debug("CK (hex): %s", res_str.c_str());


//logger.debug("First 4 bytes of k: %02x %02x %02x %02x", 
  //  (int)k[0], (int)k[1], (int)k[2], (int)k[3]);
   // logger.debug("First 4 bytes of ak: %02x %02x %02x %02x", 
    //(int)ak[0], (int)ak[1], (int)ak[2], (int)ak[3]);
    //for (int i = 0; i < CK_LEN; i++) {
    //logger.debug("CK[%d] = %02x", i, (int)ck[i]);
//}


    
    

  *res_len = 8;

  // Extract sqn from autn
  for (i = 0; i < 6; i++) {
    sqn[i] = autn_enb[i] ^ ak[i];
  }
  // Extract AMF from autn
  for (int i = 0; i < 2; i++) {
    amf[i] = autn_enb[6 + i];
  }

  // Generate MAC
  security_milenage_f1(k, opc, rand, sqn, amf, mac);

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
  for (i = 0; i < 16; i++) {
    if (autn[i] != autn_enb[i]) {
      result = AUTH_FAILED;
    }
  }
  
  for(int i = 0; i < 16; i++) {
    char temp[3];
    snprintf(temp, sizeof(temp), "%02x", (unsigned int)autn[i]);
    autn_str += temp;
}
logger.debug("AUTN (hex): %s", autn_str.c_str());

for(int i = 0; i < 16; i++) {
    char temp[3];
    snprintf(temp, sizeof(temp), "%02x", (unsigned int)autn_enb[i]);
    autn_enb_str += temp;
}
logger.debug("AUT_ENB (hex): %s", autn_enb_str.c_str());

  for (i = 0; i < 6; i++) {
    ak_xor_sqn[i] = sqn[i] ^ ak[i];
  }
  for(int i = 0; i < 6; i++) {
    char temp[3];
    snprintf(temp, sizeof(temp), "%02x", (unsigned int)ak_xor_sqn[i]);
    ak_xor_sqn_str += temp;
}
logger.debug("ak_xor_sqn (hex): %s", ak_xor_sqn_str.c_str());

  logger.debug(ck, CK_LEN, "CK:");
  logger.debug(ik, IK_LEN, "IK:");
  logger.debug(ak, AK_LEN, "AK:");
  logger.debug(sqn, 6, "sqn:");
  logger.debug(amf, 2, "amf:");
  logger.debug(mac, 8, "mac:");

  return result;
}

// 3GPP TS 34.108 version 10.0.0 Section 8
auth_result_t usim::gen_auth_res_xor(uint8_t* rand, uint8_t* autn_enb, uint8_t* res, int* res_len, uint8_t* ak_xor_sqn)
{
  auth_result_t result = AUTH_OK;
  uint8_t       sqn[6];
  uint8_t       res_[16];

  logger.debug(k, 16, "K:");

  // Use RAND and K to compute RES, CK, IK and AK
  security_xor_f2345(k, rand, res_, ck, ik, ak);

  for (uint32_t i = 0; i < 8; i++) {
    res[i] = res_[i];
  }

  *res_len = 8;

  // Extract sqn from autn
  for (uint32_t i = 0; i < 6; i++) {
    sqn[i] = autn_enb[i] ^ ak[i];
  }
  // Extract AMF from autn
  for (uint32_t i = 0; i < 2; i++) {
    amf[i] = autn_enb[6 + i];
  }

  // Generate MAC
  security_xor_f1(k, rand, sqn, amf, mac);

  // Construct AUTN
  for (uint32_t i = 0; i < 6; i++) {
    autn[i] = sqn[i] ^ ak[i];
  }
  for (uint32_t i = 0; i < 2; i++) {
    autn[6 + i] = amf[i];
  }
  for (uint32_t i = 0; i < 8; i++) {
    autn[8 + i] = mac[i];
  }

  // Compare AUTNs
  for (uint32_t i = 0; i < 16; i++) {
    if (autn[i] != autn_enb[i]) {
      result = AUTH_FAILED;
    }
  }


  logger.debug(ck, CK_LEN, "CK:");
  logger.debug(ik, IK_LEN, "IK:");
  logger.debug(ak, AK_LEN, "AK:");
  logger.debug(sqn, 6, "sqn:");
  logger.debug(amf, 2, "amf:");
  logger.debug(mac, 8, "mac:");

  for (uint32_t i = 0; i < 6; i++) {
    ak_xor_sqn[i] = sqn[i] ^ ak[i];
  }

  return result;
}


std::string usim::get_mnc_str(const uint8_t* imsi_vec, std::string mcc_str)
{
  uint32_t           mcc_len = 3;
  uint32_t           mnc_len = 2;
  std::ostringstream mnc_oss;

  // US MCC uses 3 MNC digits
  if (!mcc_str.compare("310") || !mcc_str.compare("311") || !mcc_str.compare("312") || !mcc_str.compare("313") ||
      !mcc_str.compare("316")) {
    mnc_len = 3;
  }

  for (uint32_t i = mcc_len; i < mcc_len + mnc_len; i++) {
    mnc_oss << (int)imsi_vec[i];
  }

  return mnc_oss.str();
}

void usim::str_to_hex(std::string str, uint8_t* hex)
{
  uint32_t    i;
  const char* h_str = str.c_str();
  uint32_t    len   = str.length();

  for (i = 0; i < len / 2; i++) {
    if (h_str[i * 2 + 0] >= '0' && h_str[i * 2 + 0] <= '9') {
      hex[i] = (h_str[i * 2 + 0] - '0') << 4;
    } else if (h_str[i * 2 + 0] >= 'A' && h_str[i * 2 + 0] <= 'F') {
      hex[i] = ((h_str[i * 2 + 0] - 'A') + 0xA) << 4;
    } else {
      hex[i] = ((h_str[i * 2 + 0] - 'a') + 0xA) << 4;
    }

    if (h_str[i * 2 + 1] >= '0' && h_str[i * 2 + 1] <= '9') {
      hex[i] |= h_str[i * 2 + 1] - '0';
    } else if (h_str[i * 2 + 1] >= 'A' && h_str[i * 2 + 1] <= 'F') {
      hex[i] |= (h_str[i * 2 + 1] - 'A') + 0xA;
    } else {
      hex[i] |= (h_str[i * 2 + 1] - 'a') + 0xA;
    }
  }
}

} // namespace srsue
