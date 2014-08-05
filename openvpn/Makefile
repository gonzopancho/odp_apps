# Copyright (c) 2013, Linaro Limited
# All rights reserved.
#
# SPDX-License-Identifier:     BSD-3-Clause

OPENVPN_REPO=git://openvpn.git.sourceforge.net/gitroot/openvpn/openvpn.git
OPENVPN_DIR=openvpn.git
OPENVPN_VERSION=cd6555e0159987ef264789f4976053ce2aa5fc20

ODP_DIR ?= $(PWD)/../odp.git

.PHONY: all
all: openvpn odp_ipcd

.PHONY: clean
clean: clean_openvpn clean_odp_ipcd

.PHONY: openvpn
openvpn:
	@if [ ! -d $(OPENVPN_DIR) ];\
	then\
		git clone $(OPENVPN_REPO) $(OPENVPN_DIR);\
	else\
		cd $(OPENVPN_DIR);\
		git fetch --all;\
	fi

	cd $(OPENVPN_DIR) \
	&& git checkout $(OPENVPN_VERSION) \
	&& git am ../patches/*.patch \
	&& autoreconf -i -v -f \
	&& ./configure --disable-snappy
	make -C $(OPENVPN_DIR)

.PHONY: clean_openvpn
clean_openvpn:
	if [-e $(OPENVPN_DIR)/Makefile ]; then $(MAKE) -C $(OPENVPN_DIR) clean; fi
	if [ -d $(OPENVPN_DIR) ]; then $(MAKE) -C $(OPENVPN_DIR) distclean; fi

.PHONY: clean_odp_ipcd
clean_odp_ipcd:
	make -C odp_ipcd clean

.PHONY: odp_ipcd
odp_ipcd:
	make -C odp_ipcd

.PHONY: distclean
distclean:
	rm -rf ./$(OPENVPN_DIR)
	make -C odp_ipcd clean
