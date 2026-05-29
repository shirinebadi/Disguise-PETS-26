cmake_minimum_required(VERSION 3.10)
enable_language(C CXX ASM)

# # Check for required environment variables
if (NOT DEFINED ENV{LIBSODIUM_T_DIR})
  message(FATAL_ERROR "Please set LIBSODIUM_T_DIR")
endif()
set(LIBSODIUM_C_DIR $ENV{LIBSODIUM_T_DIR})



# Set paths to the libraries
# Define targets and sources
set(eapp_bin fpga-auth)
set(eapp_src eapp/fpga-auth.c eapp/edge_wrapper.c eapp/channel.c eapp/usim.c eapp/aes.c)
set(host_bin fpga-auth-runner)
set(host_src host/host-fpga.cpp host/edge_wrapper.cpp)
set(package_name "fpga-auth.ke")
set(package_script "./fpga-auth-runner fpga-auth eyrie-rt loader.bin \"$@\"")
set(eyrie_plugins "none")

# EAPP target
add_executable(${eapp_bin} ${eapp_src})
target_link_libraries(${eapp_bin} 
  PRIVATE ${KEYSTONE_LIB_EAPP} 
  PRIVATE ${KEYSTONE_LIB_EDGE}
  PRIVATE ${LIBSODIUM_C_DIR}/.libs/libsodium.a


)
target_include_directories(${eapp_bin}
  PRIVATE include
  PUBLIC ${KEYSTONE_SDK_DIR}/include/app
PUBLIC ${KEYSTONE_SDK_DIR}/include/edge
PRIVATE ${LIBSODIUM_C_DIR}/include


)
target_compile_options(${eapp_bin} PRIVATE -O0 -fno-builtin)
set_target_properties(${eapp_bin} PROPERTIES COMPILE_FLAGS "-save-temps")

set_target_properties(${eapp_bin}
  PROPERTIES LINK_FLAGS "-nostdlib -static -T ${CMAKE_CURRENT_SOURCE_DIR}/app.lds"
)


# Host target
add_executable(${host_bin} ${host_src})
target_link_libraries(${host_bin}
  ${KEYSTONE_LIB_HOST} ${KEYSTONE_LIB_EDGE} ${KEYSTONE_LIB_VERIFIER})
  
set_target_properties(${host_bin}
  PROPERTIES 
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED YES 
    CXX_EXTENSIONS NO
)
target_include_directories(${host_bin}
  PUBLIC ${KEYSTONE_SDK_DIR}/include/common
  PUBLIC ${KEYSTONE_SDK_DIR}/include/host
  PUBLIC ${KEYSTONE_SDK_DIR}/include/edge
  PUBLIC ${KEYSTONE_SDK_DIR}/include/verifier
)

# Eyrie runtime
set(eyrie_files_to_copy .options_log eyrie-rt loader.bin)
add_eyrie_runtime(${eapp_bin}-eyrie
  ${eyrie_plugins}
  ${eyrie_files_to_copy})

# Packaging
add_keystone_package(${eapp_bin}-package
  ${package_name}
  ${package_script}
  ${eyrie_files_to_copy} ${eapp_bin} ${host_bin}
)

add_dependencies(${eapp_bin}-package ${eapp_bin}-eyrie)

# Add package to the top-level target
add_dependencies(examples ${eapp_bin}-package)
