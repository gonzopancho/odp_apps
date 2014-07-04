/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * @example odp_pktio.c  ODP packet IO example for Snort application
 */

#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>

#include <odp.h>
#include <helper/odp_linux.h>
#include <helper/odp_packet_helper.h>
#include <helper/odp_eth.h>
#include <helper/odp_ip.h>

/* Snort */
#include <api/daq_common.h>
#include "snort.h"

#define MAX_WORKERS            32
#define SHM_PKT_POOL_SIZE      (512*2048)
#define SHM_PKT_POOL_BUF_SIZE  1856
#define MAX_PKT_BURST          16

#define APPL_MODE_PKT_BURST    0
#define APPL_MODE_PKT_QUEUE    1

#define PRINT_APPL_MODE(x) printf("%s(%i)\n", #x, (x))

/** Get rid of path in filename - only for unix-type paths using '/' */
#define NO_PATH(file_name) (strrchr((file_name), '/') ? \
			    strrchr((file_name), '/') + 1 : (file_name))
/**
 * Parsed command line application arguments
 */
typedef struct {
	int core_count;
	int if_count;		/**< Number of interfaces to be used */
	char **if_names;	/**< Array of pointers to interface names */
	int mode;		/**< Packet IO mode */
	int type;		/**< Packet IO type */
	int fanout;		/**< Packet IO fanout */
	odp_buffer_pool_t pool;	/**< Buffer pool for packet IO */
} appl_args_t;

/**
 * Thread specific arguments
 */
typedef struct {
	char *pktio_dev;	/**< Interface name to use */
	odp_buffer_pool_t pool;	/**< Buffer pool for packet IO */
	int mode;		/**< Thread mode */
	int type;		/**< Thread i/o type */
	int fanout;		/**< Thread i/o fanout */
} thread_args_t;

/**
 * Grouping of both parsed CL args and thread specific args - alloc together
 */
typedef struct {
	/** Application (parsed) arguments */
	appl_args_t appl;
	/** Thread specific arguments */
	thread_args_t thread[MAX_WORKERS];
} args_t;

/** Global pointer to args */
static args_t *args;

/* helper funcs */
static void parse_args(int argc, char *argv[], appl_args_t *appl_args);
static void print_info(char *progname, appl_args_t *appl_args);
static void usage(char *progname);

static odp_spinlock_t lock;

static void analyze_packet_in_snort(odp_packet_t pkt, int thr)
{
	DAQ_PktHdr_t daqhdr;
	const uint8_t *data;
	DAQ_Verdict verd;

	data = odp_packet_l2(pkt);
	if (!data) {
		return;
	}

	gettimeofday(&daqhdr.ts, NULL);
	daqhdr.caplen = odp_buffer_size(pkt);
	daqhdr.pktlen = odp_packet_get_len(pkt);
	daqhdr.ingress_index = thr;
	daqhdr.egress_index =  DAQ_PKTHDR_UNKNOWN;
	daqhdr.ingress_group = DAQ_PKTHDR_UNKNOWN;
	daqhdr.egress_group = DAQ_PKTHDR_UNKNOWN;
	daqhdr.flags = 0;
	daqhdr.opaque = 0;
	daqhdr.priv_ptr = NULL;
	daqhdr.address_space_id = 0;

	/* Pass packet to Snort */
	odp_spinlock_lock(&lock);
	verd = PacketCallback( "NULL", &daqhdr, data);
	odp_spinlock_unlock(&lock);
	return;
}

static int snort_analyze_packets_tbl(odp_packet_t pkt_tbl[], unsigned len, int thr)
{
	odp_packet_t pkt;
	unsigned pkt_cnt = len;
	unsigned i, j;

	for (i = 0; i < len; ++i) {
		pkt = pkt_tbl[i];
		analyze_packet_in_snort(pkt, thr);
		odp_packet_free(pkt);
	}

	return pkt_cnt;
}

/**
 * Packet IO loopback worker thread using ODP queues
 *
 * @param arg  thread arguments of type 'thread_args_t *'
 */
static void *pktio_queue_thread(void *arg)
{
	int thr;
	odp_buffer_pool_t pkt_pool;
	odp_pktio_t pktio;
	thread_args_t *thr_args;
	odp_queue_t outq_def;
	odp_queue_t inq_def;
	char inq_name[ODP_QUEUE_NAME_LEN];
	odp_queue_param_t qparam;
	odp_packet_t pkt;
	odp_buffer_t buf;
	int ret;
	unsigned long pkt_cnt = 0;
	unsigned long err_cnt = 0;
	odp_pktio_params_t params;
	socket_params_t *sock_params = &params.sock_params;

	thr = odp_thread_id();
	thr_args = arg;

	printf("Pktio thread [%02i] starts, pktio_dev:%s\n", thr,
	       thr_args->pktio_dev);

	/* Lookup the packet pool */
	pkt_pool = odp_buffer_pool_lookup("packet_pool");
	if (pkt_pool == ODP_BUFFER_POOL_INVALID) {
		ODP_ERR("  [%02i] Error: pkt_pool not found\n", thr);
		return NULL;
	}

	/* Open a packet IO instance for this thread */
	sock_params->type = thr_args->type;
	sock_params->fanout = thr_args->fanout;
	pktio = odp_pktio_open(thr_args->pktio_dev, pkt_pool, &params);
	if (pktio == ODP_PKTIO_INVALID) {
		ODP_ERR("  [%02i] Error: pktio create failed\n", thr);
		return NULL;
	}

	/*
	 * Create and set the default INPUT queue associated with the 'pktio'
	 * resource
	 */
	qparam.sched.prio  = ODP_SCHED_PRIO_DEFAULT;
	qparam.sched.sync  = ODP_SCHED_SYNC_ATOMIC;
	qparam.sched.group = ODP_SCHED_GROUP_DEFAULT;
	snprintf(inq_name, sizeof(inq_name), "%i-pktio_inq_def", (int)pktio);
	inq_name[ODP_QUEUE_NAME_LEN - 1] = '\0';

	inq_def = odp_queue_create(inq_name, ODP_QUEUE_TYPE_PKTIN, &qparam);
	if (inq_def == ODP_QUEUE_INVALID) {
		ODP_ERR("  [%02i] Error: pktio queue creation failed\n", thr);
		return NULL;
	}

	ret = odp_pktio_inq_setdef(pktio, inq_def);
	if (ret != 0) {
		ODP_ERR("  [%02i] Error: default input-Q setup\n", thr);
		return NULL;
	}

	printf("  [%02i] created pktio:%02i, queue mode (ATOMIC queues)\n"
	       "          default pktio%02i-INPUT queue:%u\n",
		thr, pktio, pktio, inq_def);

	/* Loop packets */
	for (;;) {
		odp_pktio_t pktio_tmp;

#if 1
		/* Use schedule to get buf from any input queue */
		buf = odp_schedule(NULL, ODP_SCHED_WAIT);
#else
		/* Always dequeue from the same input queue */
		buf = odp_queue_deq(inq_def);
#endif


		if (!odp_buffer_is_valid(buf)) {
			continue;
		}

		pkt = odp_packet_from_buffer(buf);

		analyze_packet_in_snort(pkt, thr);
		odp_buffer_free(buf);
		pc.total_from_daq++;
	}

/* unreachable */
}

/**
 * Packet IO loopback worker thread using bursts from/to IO resources
 *
 * @param arg  thread arguments of type 'thread_args_t *'
 */
static void *pktio_ifburst_thread(void *arg)
{
	int thr;
	odp_buffer_pool_t pkt_pool;
	odp_pktio_t pktio;
	thread_args_t *thr_args;
	int pkts, pkts_ok;
	odp_packet_t pkt_tbl[MAX_PKT_BURST];
	unsigned long pkt_cnt = 0;
	unsigned long err_cnt = 0;
	unsigned long tmp = 0;
	odp_pktio_params_t params;
	socket_params_t *sock_params = &params.sock_params;

	thr = odp_thread_id();
	thr_args = arg;

	printf("Pktio thread [%02i] starts, pktio_dev:%s\n", thr,
	       thr_args->pktio_dev);

	/* Lookup the packet pool */
	pkt_pool = odp_buffer_pool_lookup("packet_pool");
	if (pkt_pool == ODP_BUFFER_POOL_INVALID) {
		ODP_ERR("  [%02i] Error: pkt_pool not found\n", thr);
		return NULL;
	}

	/* Open a packet IO instance for this thread */

	sock_params->type = thr_args->type;
	sock_params->fanout = thr_args->fanout;
	pktio = odp_pktio_open(thr_args->pktio_dev, pkt_pool, &params);
	if (pktio == ODP_PKTIO_INVALID) {
		ODP_ERR("  [%02i] Error: pktio create failed.\n", thr);
		return NULL;
	}

	printf("  [%02i] created pktio:%02i, burst mode\n",
	       thr, pktio);

	/* Loop packets */
	for (;;) {
		pkts = odp_pktio_recv(pktio, pkt_tbl, MAX_PKT_BURST);
		if (pkts > 0) {
			snort_analyze_packets_tbl(pkt_tbl, pkts, thr);
			pc.total_from_daq += pkts;
		}
	}

/* unreachable */
}

/**
 * ODP packet example main function
 */
int do_odp_init(int argc, char *argv[])
{

	odp_buffer_pool_t pool;
	int thr_id;
	void *pool_base;
	int i;
	int first_core;


	/* Init ODP before calling anything else */
	if (odp_init_global()) {
		ODP_ERR("Error: ODP global init failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Reserve memory for args from shared mem */
	args = odp_shm_reserve("shm_args", sizeof(args_t), ODP_CACHE_LINE_SIZE);
	if (args == NULL) {
		ODP_ERR("Error: shared mem alloc failed.\n");
		exit(EXIT_FAILURE);
	}
	memset(args, 0, sizeof(*args));

	/* Parse -i argument, other arguments will be parsed by Snort. */
	parse_args(argc, argv, &args->appl);

	char *tmp = getenv("ODP_CORES");
	if (tmp)
		args->appl.core_count = atoi(tmp);
	else
		args->appl.core_count = 1;

	/* always use fanout. */
	args->appl.fanout = 1;

	/* Use queque mode by default */
	tmp = getenv("ODP_PTK_BURST");
	if (tmp)
		args->appl.mode = APPL_MODE_PKT_BURST;
	else
		args->appl.mode = APPL_MODE_PKT_QUEUE;


	tmp = getenv("ODP_PKTIO_TYPE_SOCKET");
	if (tmp)
		args->appl.type = atoi(tmp);
	else
		args->appl.type = ODP_PKTIO_TYPE_SOCKET_BASIC;

	switch (args->appl.type) {
	case ODP_PKTIO_TYPE_SOCKET_MMSG:
		printf("using ODP_PKTIO_TYPE_SOCKET_MMSG\n");
		break;
	case ODP_PKTIO_TYPE_SOCKET_MMAP:
		printf("using ODP_PKTIO_TYPE_SOCKET_MMAP\n");
		break;
	case ODP_PKTIO_TYPE_SOCKET_BASIC:
	default:
		printf("using ODP_PKTIO_TYPE_SOCKET_BASIC\n");
		break;
	}

	/* Print both system and application information */
	print_info(NO_PATH(argv[0]), &args->appl);

	/* Init this thread */
	thr_id = odp_thread_create(0);
	odp_init_local(thr_id);

	/* Create packet pool */
	pool_base = odp_shm_reserve("shm_packet_pool",
				    SHM_PKT_POOL_SIZE, ODP_CACHE_LINE_SIZE);
	if (pool_base == NULL) {
		ODP_ERR("Error: packet pool mem alloc failed.\n");
		exit(EXIT_FAILURE);
	}

	pool = odp_buffer_pool_create("packet_pool", pool_base,
				      SHM_PKT_POOL_SIZE,
				      SHM_PKT_POOL_BUF_SIZE,
				      ODP_CACHE_LINE_SIZE,
				      ODP_BUFFER_TYPE_PACKET);
	if (pool == ODP_BUFFER_POOL_INVALID) {
		ODP_ERR("Error: packet pool create failed.\n");
		exit(EXIT_FAILURE);
	}
	odp_buffer_pool_print(pool);

	return 0;
}

void odp_snort_run_threads(void)
{
	odp_linux_pthread_t thread_tbl[MAX_WORKERS];
	int i;
	int core_count;
	int num_workers;
	int first_core;

	core_count  = odp_sys_core_count();
	num_workers = core_count;

	/*
	 * By default core #0 runs Linux kernel background tasks.
	 * Start mapping thread from core #1
	 */
	first_core = 1;

	if (core_count == 1)
		first_core = 0;

	printf("First core:         %i\n\n", first_core);

	if (args->appl.core_count)
		num_workers = args->appl.core_count;

	if (num_workers > MAX_WORKERS)
		num_workers = MAX_WORKERS;

	printf("Num worker threads: %i\n", num_workers);

	/* Clear Snort stats */
	memset(&pc, 0, sizeof(PacketCount));
	/* Set snort start time */
	TimeStart();

	/* Create and init worker threads */
	memset(thread_tbl, 0, sizeof(thread_tbl));
	for (i = 0; i < num_workers; ++i) {
		void *(*thr_run_func) (void *);
		int core;
		int if_idx;

		core = (first_core + i) % core_count;

		if_idx = i % args->appl.if_count;

		args->thread[i].pktio_dev = args->appl.if_names[if_idx];
		args->thread[i].mode = args->appl.mode;
		args->thread[i].type = args->appl.type;
		args->thread[i].fanout = args->appl.fanout;

		if (args->appl.mode == APPL_MODE_PKT_BURST)
			thr_run_func = pktio_ifburst_thread;
		else /* APPL_MODE_PKT_QUEUE */
			thr_run_func = pktio_queue_thread;
		/*
		 * Create threads one-by-one instead of all-at-once,
		 * because each thread might get different arguments.
		 * Calls odp_thread_create(cpu) for each thread
		 */
		odp_linux_pthread_create(thread_tbl, 1, core, thr_run_func,
					 &args->thread[i]);
	}

	/* Master thread waits for other threads to exit */
	odp_linux_pthread_join(thread_tbl, num_workers);
	printf("Exit\n\n");
}

/**
 * Parse and store the command line arguments
 *
 * @param argc       argument count
 * @param argv[]     argument vector
 * @param appl_args  Store application arguments here
 */
static void parse_args(int argc, char *argv[], appl_args_t *appl_args)
{
	int opt;
	int long_index;
	char *names, *str, *token, *save;
	size_t len;
	int i;
	static struct option longopts[] = {
		{"interface", required_argument, NULL, 'i'},	/* return 'i' */
		{NULL, 0, NULL, 0}
	};

	while (1) {
		opt = getopt_long(argc, argv, "+i:",
				  longopts, &long_index);
		if (opt == -1)
			break;	/* No more options */

		switch (opt) {
		case 'i':
			len = strlen(optarg);
			if (len == 0) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}
			len += 1;	/* add room for '\0' */

			names = malloc(len);
			if (names == NULL) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}

			/* count the number of tokens separated by ',' */
			strcpy(names, optarg);
			for (str = names, i = 0;; str = NULL, i++) {
				token = strtok_r(str, ",", &save);
				if (token == NULL)
					break;
			}
			appl_args->if_count = i;

			if (appl_args->if_count == 0) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}

			/* allocate storage for the if names */
			appl_args->if_names =
			    calloc(appl_args->if_count, sizeof(char *));

			/* store the if names (reset names string) */
			strcpy(names, optarg);
			for (str = names, i = 0;; str = NULL, i++) {
				token = strtok_r(str, ",", &save);
				if (token == NULL)
					break;
				appl_args->if_names[i] = token;
			}
			break;
		default:
			break;
		}
	}

	optind = 1;		/* reset 'extern optind' from the getopt lib */
}

/**
 * Print system and application info
 */
static void print_info(char *progname, appl_args_t *appl_args)
{
	int i;

	printf("\n"
	       "ODP system info\n"
	       "---------------\n"
	       "ODP API version: %s\n"
	       "CPU model:       %s\n"
	       "CPU freq (hz):   %"PRIu64"\n"
	       "Cache line size: %i\n"
	       "Core count:      %i\n"
	       "\n",
	       odp_version_api_str(), odp_sys_cpu_model_str(), odp_sys_cpu_hz(),
	       odp_sys_cache_line_size(), odp_sys_core_count());

	printf("Running ODP appl: \"%s\"\n"
	       "-----------------\n"
	       "IF-count:        %i\n"
	       "Using IFs:      ",
	       progname, appl_args->if_count);
	for (i = 0; i < appl_args->if_count; ++i)
		printf(" %s", appl_args->if_names[i]);
	printf("\n"
	       "Mode:            ");
	if (appl_args->mode == APPL_MODE_PKT_BURST)
		PRINT_APPL_MODE(APPL_MODE_PKT_BURST);
	else
		PRINT_APPL_MODE(APPL_MODE_PKT_QUEUE);
	printf("\n\n");
	fflush(NULL);
}

/**
 * Prinf usage information
 */
static void usage(char *progname)
{
	printf("\n"
	       "Usage: %s OPTIONS\n"
	       "  E.g. %s -i eth1,eth2,eth3 -m 0\n"
	       "\n"
	       "OpenDataPlane example application.\n"
	       "\n"
	       "Mandatory OPTIONS:\n"
	       "  -i, --interface Eth interfaces (comma-separated, no spaces)\n"
	       "  -m, --mode      0: Burst send&receive packets (no queues)\n"
	       "                  1: Send&receive packets through ODP queues.\n"
	       " -t, --type   1: ODP_PKTIO_TYPE_SOCKET_BASIC\n"
	       "	      2: ODP_PKTIO_TYPE_SOCKET_MMSG\n"
	       "	      3: ODP_PKTIO_TYPE_SOCKET_MMAP\n"
	       "	      4: ODP_PKTIO_TYPE_NETMAP\n"
	       "	 Default: 3: ODP_PKTIO_TYPE_SOCKET_MMAP\n"
	       " -f, --fanout 0: off 1: on (Default 1: on)\n"
	       "\n"
	       "Optional OPTIONS\n"
	       "  -c, --count <number> Core count.\n"
	       "  -h, --help           Display help and exit.\n"
	       "\n", NO_PATH(progname), NO_PATH(progname)
	    );
}
