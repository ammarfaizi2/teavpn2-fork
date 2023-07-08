#
# SPDX-License-Identifier: GPL-2.0-only
#
# @author Ammar Faizi <ammarfaizi2@gmail.com> https://www.facebook.com/ammarfaizi2
# @license GPL-2.0-only
#
# Copyright (C) 2021  Ammar Faizi
#

DEP_DIRS += $(BASE_DEP_DIR)/src/teavpn2

OBJ_CC += \
	$(BASE_DIR)/src/teavpn2/print.o \
	$(BASE_DIR)/src/teavpn2/helpers.o

ifeq ($(CONFIG_TEAVPN_SERVER),y)
OBJ_CC += $(BASE_DIR)/src/teavpn2/server.o
endif

ifeq ($(CONFIG_TEAVPN_CLIENT),y)
OBJ_CC += $(BASE_DIR)/src/teavpn2/client.o
endif

ifeq ($(CONFIG_LINUX),y)
include $(BASE_DIR)/src/teavpn2/linux/Makefile
endif
