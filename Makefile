.PHONY: libpcap openvpn

all: libpcap snort

libpcap: odp
	make -C libpcap ODP_DIR=$(PWD)/../odp-bin

openvpn: odp
	make -C openvpn

snort: odp
	make -C snort ODP_DIR=$(PWD)/../odp-bin

odp:
	if [ ! -d odp.git ]; \
		then git clone http://git.linaro.org/git/lng/odp.git odp.git; \
	fi
	cd odp.git; git checkout -f HEAD; \
		git pull; git clean -f -d -x; \
		./bootstrap; \
		./configure --prefix=$(PWD)/../odp-bin --with-pic; \
		make; make install

distclean:
	rm -rf odp.git
	make -C libpcap distclean
	make -C openvpn distclean
