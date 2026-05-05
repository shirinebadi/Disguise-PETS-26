################################################################################
#
# srsUE
#
################################################################################

SRSRAN_SITE = $(TOPDIR)/dl/srsue/srsRAN_4G
SRSRAN_SITE_METHOD = local
SRSRAN_LICENSE = AGPL-3.0
SRSRAN_LICENSE_FILES = LICENSE
SRSRAN_DEPENDENCIES = boost fftw-single mbedtls lksctp-tools libconfig pcsc-lite
SRSRAN_INSTALL_STAGING = YES
SRSRAN_INSTALL_TARGET = YES
SRSRAN_CONF_OPTS = -DBUILD_DEMOS=ON\
    -DCMAKE_CXX_FLAGS="-march=rv64gc -mabi=lp64d -pthread -latomic"

ifeq ($(BR2_PACKAGE_ZEROMQ),y)
SRSRAN_DEPENDENCIES += zeromq
endif

SRSRAN_SUPPORTS_IN_SOURCE_BUILD = NO

$(eval $(cmake-package))
