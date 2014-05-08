.PHONY: libpcap openvpn

all: openvpn libpcap

libpcap: odp
	make -C libpcap ODP_DIR=$(PWD)/odp.git

openvpn: odp
	make -C openvpn

odp:
	if [ ! -d odp.git ]; \
		then git clone http://git.linaro.org/git/lng/odp.git odp.git; \
	fi
	cd odp.git; make libs_install  CFLAGS="-fPIC"

distclean:
	rm -rf odp.git
	make -C libpcap distclean
	make -C openvpn distclean
