#
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
#

INCLUDE_DIR += -I$(BASE_DIR)/src/teavpn2
DEP_DIRS += $(BASE_DEP_DIR)/src/teavpn2

OBJ_CC += \
	$(BASE_DIR)/src/teavpn2/helpers.o \
	$(BASE_DIR)/src/teavpn2/main.o

ifeq ($(CONFIG_TEAVPN_SERVER),y)
include $(BASE_DIR)/src/teavpn2/server/Makefile
endif

ifeq ($(CONFIG_TEAVPN_CLIENT),y)
include $(BASE_DIR)/src/teavpn2/client/Makefile
endif

include $(BASE_DIR)/src/teavpn2/ap/Makefile
