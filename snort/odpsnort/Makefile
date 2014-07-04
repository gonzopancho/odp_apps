SNORT=$(PWD)/../snort-2.9.6.0-lib
CFLAGS += -I/$(SNORT)/src
LDFLAGS += -L/$(SNORT)/src
LDFLAGS += -L/$(SNORT)/src/dynamic-plugins

DAQ=$(PWD)/../daq-2.0.2
DAQ_LIB_DIR = "$(DAQ)/api/.libs"
LDFLAGS += "-L$(DAQ_LIB_DIR)"

DAQ_LIB = "$(DAQ)/api/.libs/libdaq.a"


LIBDNET = "/usr/local/lib/libdnet.a"
LIBSNORT = "/usr/local/lib/libsnort.a"

INC = "-I$(SNORT)/src/sfutil"
INC += "-I$(SNORT)/src/dynamic-plugins"
INC += "-I$(SNORT)/src/preprocessors"
INC += "-I$(SNORT)/src/dynamic-preprocessors/include"
INC += "-I$(SNORT)/src/detection-plugins"
INC += "-I$(SNORT)/src/target-based"
INC += "-I$(SNORT)/src/control"
INC += "-I$(SNORT)/src/file-process"
INC += "-I$(SNORT)/src/file-process/libs"
INC += "-I$(SNORT)/src/preprocessors/Stream5"
INC += "-I$(SNORT)/src"
INC += "-I$(SNORT)"

ODP_DIR = $(PWD)/../../odp.git
ODP_LIB = $(ODP_DIR)/build/lib/libodp.a
ODP_CFLAGS += -I$(ODP_DIR)/include
ODP_CFLAGS += -I$(ODP_DIR)/platform/linux-generic/include
ODP_CFLAGS += -I$(ODP_DIR)/platform/linux-generic/include/api

LDFLAGS += $(ODP_LIB)

DAQ = $(PWD)/../daq-2.0.2
ODP_CFLAGS += -I$(DAQ)

all:
	$(CC) -c -O0 -g snort.c ${CFLAGS} ${LDFLAGS} $(INC) -o snort.o
	$(CC) -c -O0 -g -pthread ${INC}  $(ODP_CFLAGS) odp_pktio.c -o odp_pktio.o
	$(CC) snort.o odp_pktio.o  ${CFLAGS} ${LDFLAGS} $(INC)  ${LIBSNORT} ${DAQ_LIB} ${LIBDNET}  -ldl -lz -lpcap -pthread -lpcre -lssl -lcrypto -lm -lrt -o odp-snort
clean:
	rm -rf odp-snort *.o
run:
	export LD_LIBRARY_PATH="/usr/local/lib";./odp-snort -i eth0


