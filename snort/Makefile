.PHONY: all odp daq snort odpsnort
all: snort

DAQ="daq-2.0.2"
daqprep:
	rm -rf ${DAQ}
	tar xpvfz ./download/daq-2.0.2.tar.gz
	cd ${DAQ}; patch -p1 < ../daq-patches/0001-implement-odp-daq-module.patch


daq: daqprep libdnet
	cd ${DAQ}; autoreconf
	cd ${DAQ}; ./configure CFLAGS="-I../../../odp.git/build/include -g -O0" LDFLAGS="-g -L../../../odp.git/build/lib"
	cd ${DAQ}; make
	cd ${DAQ}; make install


snortprep:
	rm -rf snort-2.9.6.0
	tar xpfz download/snort-2.9.6.0.tar.gz

SNORT="snort-2.9.6.0-odp"
snort: snortprep daq
	rm -rf $(SNORT)
	cp -a snort-2.9.6.0 $(SNORT)
	cd ${SNORT}; patch -p2 < ../snort-patches/0001-add-dependancy-for-lrt.patch
	cd ${SNORT}; ./configure --disable-static-daq LDFLAGS="-lrt"
	cd ${SNORT}; make
	cd ${SNORT}; make install

LIBDNET="libdnet-1.11"
libdnet:
	#wget http://prdownloads.sourceforge.net/libdnet/libdnet-1.11.tar.gz
	tar xpfz ./download/libdnet-1.11.tar.gz
	cd ${LIBDNET}; ./configure
	cd ${LIBDNET}; make
	cd ${LIBDNET}; make install

run:
	export LD_LIBRARY_PATH="/usr/local/lib"; snort --daq-dir=${PWD}/daq-2.0.2/os-daq-modules/.libs/ --daq=odp -i eth0 -n 10

SNORT-lib="snort-2.9.6.0-lib"
snortlib: snortprep daq
	rm -rf ${SNORT-lib}
	cp -a snort-2.9.6.0 ${SNORT-lib}
	cd ${SNORT-lib}; patch -p2 <  ../snort-patches/0001-add-dependancy-for-lrt.patch
	cd ${SNORT-lib}; patch -p1 <  ../lib-patches/0001-Compile-Snort-as-static-library.patch
	cd ${SNORT-lib}; patch -p1 <  ../lib-patches/0002-remove-static-from-needed-functions.patch
	cd ${SNORT-lib}; autoreconf
	cd ${SNORT-lib}; ./configure --disable-static-daq LDFLAGS="-lrt"
	cd ${SNORT-lib}; make

odpsnort: snortlib
	cd odpsnort; make

all: libdnet daq snort odpsnort

distclean:
	rm -rf ${DAQ}
	rm -rf ${SNORT}
	rm -rf ${SNORT-lib}
	rm -rf snort-2.9.6.1
	rm -rf snort-2.9.6.0
	rm -rf libdnet-1.11
	make -C odpsnort clean
