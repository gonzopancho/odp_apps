# Copyright (c) 2013, Linaro Limited
# All rights reserved.
#
# SPDX-License-Identifier:     BSD-3-Clause

ODP_ROOT = ../../odp-bin
ODP_APP  = odp_ipcd

ODP_LIB = $(ODP_ROOT)/lib/libodp.a
EXTRA_CFLAGS += -I$(ODP_ROOT)/include
EXTRA_CFLAGS += -I$(ODP_ROOT)/include/helper

LDFLAGS += -pthread
LDFLAGS += -lrt

OBJ_DIR = ./objs

OBJS     =
OBJS    += $(OBJ_DIR)/odp_ipcd.o

DEPS     = $(OBJS:.o=.d)

.PHONY: all
all: $(OBJ_DIR) $(ODP_APP)

-include $(DEPS)

$(OBJ_DIR):
	mkdir $(OBJ_DIR)

$(LIB):
	@echo Building $@
	$(MAKE) -C $(ODP_LIB) libs

#
# Compile rules
#
$(OBJ_DIR)/%.o: %.c
	@echo Compiling $<
	$(CC) -c -O0 -g -MD $(CFLAGS) $(EXTRA_CFLAGS) -o $@ $<

#
# Link rule
#
$(ODP_APP): $(LIB) $(OBJS)
	@echo Linking $<
	$(CC) $(OBJS) $(ODP_LIB) $(STD_LIBS) $(LDFLAGS) -o $@

.PHONY: clean
clean:
	rm -rf $(OBJ_DIR)
	rm -rf $(ODP_APP)

