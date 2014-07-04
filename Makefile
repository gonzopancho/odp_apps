.PHONY: libpcap openvpn

all: openvpn libpcap snort

libpcap: odp
	make -C libpcap ODP_DIR=$(PWD)/odp.git

openvpn: odp
	make -C openvpn

snort: odp
	make -C snort

odp:
	if [ ! -d odp.git ]; \
		then git clone http://git.linaro.org/git/lng/odp.git odp.git; \
	fi
	cd odp.git; git reset --hard a5b7d50a6ac17ef5ada2da2232764065fce48c31
	cd odp.git; patch -N -p1 < ../snort/odp-patches/0001-implement-odp_timer_disarm_all.patch
	cd odp.git; make libs_install  CFLAGS="-fPIC"

distclean:
	rm -rf odp.git
	make -C libpcap distclean
	make -C openvpn distclean
