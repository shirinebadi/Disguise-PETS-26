# Artifact Appendix 

Paper title: **Di5Guise: 5G Privacy with vSIM**

Requested Badge(s):
  - [x] **Available**
  - [ ] **Functional**
  - [ ] **Reproduced**


## Description 
This artifact accompanies the paper *"Di5Guise: 5G Privacy with vSIM"*, accepted to Issue 4 of PETs'26. It includes the source code for the vSIM software, the FPGA block design with Keystone TEE support, and the modifications to srsUE required to evaluate 5G authentication with vSIM. Together, these components enable reproduction of the system described in the paper.

The repository provides:
1. device and subsriber profile provisioning (`vsim/fpga-provision`) and operator (`provider`).
2. Modifications to srsUE (`srsue/usim.cc`) and 5G authenction (`vsim/fpga-auth`).

### Security/Privacy Issues and Ethical Concerns 

- The code does**not** disable security features or run vulnerable features.  
- There are **no human subjects or user study data** bundled in this artifact.  

## Environment 

### Accessibility 

The artifact is publicly available at:  
**https://github.com/shirinebadi/Disguise-PETS-26**

### Set up the environment 

Checkout the main README for setup and run the codes.


## Limitations 

This artifact is released under the **Available** badge.  
It provides all codes for the system, but does **not** guarantee reproducibility of full experimental results without further computational resources (e.g., access to FPGA).

## Notes on Reusability (Encouraged for all badges)

This code provides a foundation for developing stronger linkability defenses by mitigating or eliminating side-channel attacks.
