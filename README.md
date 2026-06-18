This repository contains the protoype code of the Di5Guise system published at PETS'26.

# Setup

See `ARTIFACT-APPENDIX.md` for full environment setup instructions.

# Run
## Profile Provisioning
First run the `provider/provider.cpp` for the operator server to be ready and running. Next build and run the `vsim/fpga-provision`. This will add a new subsriber and device profile.

## Authentication
Run srsran using `ZMQ` using this [tutorial](https://docs.srsran.com/projects/project/en/latest/tutorials/source/srsUE/source/index.html). Then build and run `vsim/fpga-auth`. Make sure the program is started and running. In another terminal, start the srsUE to begin the authentication and connection to network. You should see the connected logs.

For further questions, please contact me at `shirin.ebadi@colorado.edu`.


