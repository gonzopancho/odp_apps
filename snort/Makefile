.PHONY: all daq-odp
all: daq-odp

daq-odp:
	if [ ! -d daq-odp.git ]; \
		then git clone https://github.com/muvarov/daq-odp.git daq-odp.git; \
	fi
	cd daq-odp.git; autoreconf -ivf; ./configure --with-odp-path=$(ODP_DIR); make

run:
	export LD_LIBRARY_PATH="/usr/local/lib"; snort --daq-dir=${PWD}/daq-2.0.2/os-daq-modules/.libs/ --daq=odp -i eth0 -n 10

distclean:
	rm -rf daq-odp.git
