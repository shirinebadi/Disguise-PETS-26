# Artifact Appendix 

Paper title: **Di5Guise: 5G Privacy with vSIM**

Requested Badge(s):
  - [x] **Available**
  - [ ] **Functional**
  - [ ] **Reproduced**


## Description 
This artifact accompanies the paper *"Di5Guise: 5G Privacy with vSIM"*, accepted to Issue 4 of PETs'26. It includes the source code for the vSIM software, the FPGA block design with Keystone TEE support, and the modifications to srsUE required to evaluate 5G authentication with vSIM. Together, these components enable reproduction of the system described in the paper.

The repository provides:
1. Device and subscriber profile provisioning (`vsim/fpga-provision`) and operator (`provider`).
2. Modifications to srsUE (`srsue/usim.cc`) and 5G authentication (`vsim/fpga-auth`).

### Security/Privacy Issues and Ethical Concerns 

- The code does **not** disable security features or run vulnerable features.  
- There are **no human subjects or user study data** bundled in this artifact.  

## Environment 

### Accessibility 

The artifact is publicly available at:  
**https://github.com/shirinebadi/Disguise-PETS-26**

### Set up the environment 

**QEMU or FPGA:** Run the code on QEMU or an FPGA board. For FPGA, see the [Vivado RISC-V design](https://github.com/jzmoolman/vivado-risc-v). For QEMU, follow the [Keystone QEMU instructions](https://docs.keystone-enclave.org/en/v0.1-c2e5205/Getting-Started/Running-Keystone-with-QEMU.html) and add a tunnel between the host and QEMU for network access.

**Keystone:** Set up Keystone and verify the example applications run. Replace all `string.c` files in Keystone with `keystone-patches/string.c`.

**Buildroot:** Enable and build the libraries listed in `libraries.txt` in the buildroot configuration. Download and place srsUE (following the [ZeroMQ app note](https://docs.srsran.com/projects/4g/en/latest/app_notes/source/zeromq/source/index.html)) in `buildroot/dl` and add the corresponding package files to `buildroot/package`. Enable ZMQ-based packages in buildroot and ensure ZMQ is enabled during the srsUE build.

**SrsUE:** Replace `srsue/src/stack/upper/usim.cc` with the provided `srsue/usim.cc` to enable authentication via vSIM in the trusted enclave. Use the provided `ue.conf` for UE configuration.

**Libsodium:** Build Libsodium following [these instructions](https://github.com/keystone-enclave/keystone-demo/blob/master/docs/Building-libsodium.rst).

**vSIM:** Place and build `vsim/fpga-auth` in `keystone/examples` and update `examples/CMakeLists.txt` accordingly. The profile provisioning implementation is in `vsim/fpga-provision`.

### Testing the Environment

**Profile Provisioning:** First run `provider/provider.cpp` so the operator server is ready. Then build and run `vsim/fpga-provision`. This will add a new subscriber and device profile.

**Authentication:** Run srsRAN with ZMQ using this [tutorial](https://docs.srsran.com/projects/project/en/latest/tutorials/source/srsUE/source/index.html). Then build and run `vsim/fpga-auth` and confirm it is running. In a separate terminal, start srsUE to begin authentication and connection to the network. You should see connected logs.

For further questions, contact `shirin.ebadi@colorado.edu`.


## Limitations 

This artifact is released under the **Available** badge.  
It provides all codes for the system, but does **not** guarantee reproducibility of full experimental results without further computational resources (e.g., access to FPGA).

## Notes on Reusability

This code provides a foundation for developing stronger linkability defenses by mitigating or eliminating side-channel attacks.
