.PHONY: libpcap

libpcap: odp
	make -C libpcap ODP_DIR=$(PWD)/odp.git

odp:
	if [ ! -d odp.git ]; \
		then git clone http://git.linaro.org/git/lng/odp.git odp.git; \
	fi
	cd odp.git; make CFLAGS="-fPIC"; make install

all: odp libpcap

distclean:
	rm -rf odp.git
	make -C libpcap distclean
