This repository contains the protoype code of the Di5Guise system published at PETS'26.

# Setup
## QEMU or FPGA
You can either run the code on Qemu or on your FPGA board. Checkout [here](https://github.com/jzmoolman/vivado-risc-v) for The FPGA design. Otherwise, follow the instructions from [here](https://docs.keystone-enclave.org/en/v0.1-c2e5205/Getting-Started/Running-Keystone-with-QEMU.html) to setup Keystone with QEMU If using Qemu. Also, make sure to add the tunnel between your host and QEMU for network accessibility.

## Keystone
You need to setup the keystone in your environment and make sure the example applications are running. Replace the `keystone-patches/string.c` file with all the `string.c` files in the keystone. 

## Buildroot
You need to enable and build the set of libraries listed in the `libraries.txt` in the buildroot configuration. Then, download and place srsue (following the [instruction](https://docs.srsran.com/projects/4g/en/latest/app_notes/source/zeromq/source/index.html)) in the `buildroot/dl` directory, and add the corresponding package files to the `buildroot/package`. Make sure you already enabled ZMQ-based packages in the buildroot configuration and ZMQ is enabled during srsue build.

## SrsUE
Replace the `usim.cc` file with the `srsue/src/stack/upper/usim.cc` to enable authentication using vSIM in the trusted enclave. Use the `ue.conf` for UE configuration.

## vSIM
for authentication, make sure to place and build `vsim/fpga-test` in the examples directory and update the `examples/CMakeLists.txt` accordingly.
The profile provisioning implementation is located in `vsim/fpga-provision`.

# Run
## Profile Provisioning
First run the `provider/provider.cpp` for the operator server to be ready and running. Next build and run the `vsim/fpga-provision`. This will add a new subsriber and device profile.

## Authentication
Run srsran using `ZMQ` using this [tutorial](https://docs.srsran.com/projects/project/en/latest/tutorials/source/srsUE/source/index.html). Then build and run `vsim/fpga-test`. Make sure the program is started and running. In another terminal, start the srsUE to begin the authentication and connection to network. You should see the logs.


