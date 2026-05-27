This repository contains the protoype code of the Di5Guise system published at PETS'26.

# Setup
## Qemu or FPGA
You can either run the code on Qemu or on your FPGA board. The FPGA program can be found in `fpga` directory. If using Qemu, make sure to add the tunnel for network accessibility.

## Keystone
You need to setup the keystone in your environment and make sure that is running. Replace the `keystone-patches/string.c` file with all the `string.c` files in the keystone. 

## Buildroot
You need to enable and make the set of libraries required in the `libraries.txt`. Then download and place the srsue in the `buildroot/dl` directory and add the package files to the `buildroot/package`. Make sure to enable srsue when building buildroot.

## SrsUE
Replace the `usim.cc` file with the `srsue/usim.cc` to enable authentication using vSIM in the trusted enclave. If using FPGA, make sure to use the ue.conf which uses smaller df range.

## vSIM
for authentication, make sure to place and build `vsim/fpga-test` in the examples directory and modify the cMAKE accordingly.
profile provisioning is in `vsim/fpga-provision`.

# Run
## Profile Provisioning
First run the `provider/provider.cpp` for the operator server to be ready and running. Next build and run the `vsim/fpga-provision`. This will add a new subsriber and device profile.

## Authentication
Run srsran using ZMQ using this tutorial. Then build and run `vsim/fpga-test`. Make sure the program is started and running. Then, start the srsUE to begin the authentication and connection to network. You should see the logs.


