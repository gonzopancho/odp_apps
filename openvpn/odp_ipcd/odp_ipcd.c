/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * @example ODP shared memory daemon
 */

#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <arpa/inet.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <linux/if.h>
#include <sys/ioctl.h>
#include <netdb.h>

#include <odp.h>
#include <odph_linux.h>
#include <odph_eth.h>
#include <odph_ip.h>
#include <odph_udp.h>

#include "odp_ipcd.h"
#include "helper.h"

#define MAX_WORKERS            1
#define SHM_PKT_POOL_SIZE      (512*2048)
#define SHM_PKT_POOL_BUF_SIZE  1856
#define MAX_PKT_BURST          16

#define APPL_MODE_PKT_BURST    0
#define APPL_MODE_PKT_QUEUE    1

#define PRINT_APPL_MODE(x) printf("%s(%i)\n", #x, (x))

/** Get rid of path in filename - only for unix-type paths using '/' */
#define NO_PATH(file_name) (strrchr((file_name), '/') ? \
			    strrchr((file_name), '/') + 1 : (file_name))

static uint32be_t sip;
static uint32be_t dip;

/**
 * Parsed command line application arguments
 */
typedef struct {
	int if_count;		/**< Number of interfaces to be used */
	char **if_names;	/**< Array of pointers to interface names */
	int mode;		/**< Packet IO mode */
	odp_buffer_pool_t pool;	/**< Buffer pool for packet IO */
} appl_args_t;

/**
 * Thread specific arguments
 */
typedef struct {
	char *pktio_dev;	/**< Interface name to use */
	odp_buffer_pool_t pool;	/**< Buffer pool for packet IO */
	int mode;		/**< Thread mode */
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

static struct odp_ipc_shm* odp_ipc_shm = NULL;

char smac[] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
char dmac[] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

static struct odp_ipc_shm* odp_ipc_shm_init(void)
{
	int key = 5001;
	int shm_size = 4096 + 9000 + 9000;
	int shmid;
	void *shm;

	shmid = shmget(key, shm_size, 0666 | IPC_CREAT);
	if (shmid < 0) {
		printf("unble to connect to shared memory\n");
		exit(0);
	}

	shm = shmat(shmid, (char*)NULL, 0);
	if (!shm) {
		fprintf(stderr, "   Error: unable to allocate odp_ipc_shm\n");
		return NULL;
	}
	odp_ipc_shm = (void*)malloc(sizeof(struct odp_ipc_shm));
	if (!odp_ipc_shm)
		fprintf(stderr, "   Error: unable to allocate odp_ipc_shm\n");

	odp_ipc_shm->in_p = (void*)((char*)shm + 4096);
	odp_ipc_shm->in_len = (void *)((char*)shm + 100);
	odp_ipc_shm->out_p = (void*)((char*)shm + 4096  + 9000);
	odp_ipc_shm->out_len = (void*)((char*)shm + 110);

	odp_ipc_shm->magic_odp = (unsigned long *)shm;
	odp_ipc_shm->magic_app = (void*)((char*)shm + 10);

	*odp_ipc_shm->in_len = 0;
	*odp_ipc_shm->out_len = 0;

	*odp_ipc_shm->magic_odp = 0xbeaf;
	*odp_ipc_shm->magic_odp = 0x0;

	printf("odp_ipc_shm reserved ok\n");
	return odp_ipc_shm;
}

/* helper funcs */
static void parse_args(int argc, char *argv[], appl_args_t *appl_args);
static void print_info(char *progname, appl_args_t *appl_args);
static void usage(char *progname);

/**
 * Packet IO loopback worker thread using ODP queues
 *
 * @param arg  thread arguments of type 'thread_args_t *'
 */
static void *pktio_queue_send_thread(void *arg)
{
	int thr;
	odp_buffer_pool_t pool;
	odp_pktio_t pktio;
	thread_args_t *thr_args;
	odp_queue_t inq_def;
	odp_queue_t outq_def;
	char inq_name[ODP_QUEUE_NAME_LEN];
	odp_queue_param_t qparam;
	odp_packet_t odp_pkt;
	odp_buffer_t odpbuf;
	int ret;
	unsigned long pkt_cnt = 0;
	odp_pktio_params_t params;
	socket_params_t *sock_params = &params.sock_params;

	thr = odp_thread_id();
	thr_args = arg;

	printf("Pktio send thread [%02i] starts, pktio_dev:%s\n", thr,
	       thr_args->pktio_dev);

	/* Lookup the packet pool */
	pool = odp_buffer_pool_lookup("packet_pool");
	if (pool == ODP_BUFFER_POOL_INVALID) {
		ODP_ERR("  [%02i] Error: pkt_pool not found\n", thr);
		return NULL;
	}

	/* Open a packet IO instance for this thread */
	sock_params->type = ODP_PKTIO_TYPE_SOCKET_MMAP;
	sock_params->fanout = 0;
	pktio = odp_pktio_open(thr_args->pktio_dev, thr_args->pool, &params);
	if (pktio == ODP_PKTIO_INVALID) {
		ODP_ERR("  [%02i] Error: pktio create failed\n", thr);
		return NULL;
	}

	/*
	 * Create and set the default INPUT queue associated with the 'pktio'
	 * resource
	 */
	qparam.sched.prio  = ODP_SCHED_PRIO_DEFAULT;
	qparam.sched.sync  = ODP_SCHED_SYNC_NONE;
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

	outq_def = odp_pktio_outq_getdef(pktio);
	if (outq_def == ODP_QUEUE_INVALID) {
		fprintf(stderr, "  Error: def output-Q query\n");
		return NULL;
	}

	printf("  [%02i] created pktio:%02i, queue mode\n"
	       "          default pktio%02i-OUT queue:%u\n",
		thr, pktio, pktio, outq_def);

	/* Loop packets */
	for (;;) {
		/* application put packet to shm. -> odp queque it to out*/
		if (*odp_ipc_shm->in_len > 0) {
			//printf("shm in_len %d\n", *odp_ipc_shm->in_len);
			odpbuf = odp_buffer_alloc(pool);
			if (odp_buffer_is_valid(odpbuf)) {
				odp_pkt = odp_packet_from_buffer(odpbuf);
				int udp_payload_len =  *odp_ipc_shm->in_len;

				odp_packet_init(odp_pkt);
				odp_packet_set_len(odp_pkt, ODP_ETHHDR_LEN + ODP_IPV4HDR_LEN + ODP_UDPHDR_LEN + udp_payload_len);

				odp_packet_set_l2_offset(odp_pkt, 20);
				odp_packet_set_l3_offset(odp_pkt, 20 + ODP_ETHHDR_LEN);
				odp_packet_set_l4_offset(odp_pkt, 20 + ODP_ETHHDR_LEN + ODP_IPV4HDR_LEN);

				//odp_packet_print(odp_pkt);

				odp_ethhdr_t *eth;
				odp_ipv4hdr_t *ip;
				odp_udphdr_t *udp;

				eth = (odp_ethhdr_t *)odp_packet_l2(odp_pkt);

				memcpy(eth->dst.addr, dmac, 6);
				memcpy(eth->src.addr, smac, 6);
				eth->type = odp_cpu_to_be_16(ODP_ETHTYPE_IPV4);

				ip = (odp_ipv4hdr_t *)odp_packet_l3(odp_pkt);
				memset(ip, 0, sizeof(odp_ipv4hdr_t));

				ip->proto = ODP_IPPROTO_UDP;
				ip->src_addr =  sip; //0x010000c3;
				ip->dst_addr =  dip; //0x020000c3;
				ip->ver_ihl = 0x45;
				ip->ttl = 64;
				ip->tot_len = odp_cpu_to_be_16(ODP_IPV4HDR_LEN + ODP_UDPHDR_LEN + udp_payload_len);
				ip->chksum = 0x0;
				ip->chksum = ip_checksum((uint16_t *)(void*)ip, sizeof(odp_ipv4hdr_t));

				udp = (odp_udphdr_t *)odp_packet_l4(odp_pkt);

				udp->src_port = odp_cpu_to_be_16(555);
				udp->dst_port = odp_cpu_to_be_16(777);
				udp->length = odp_cpu_to_be_16(sizeof(odp_udphdr_t) + udp_payload_len);
				udp->chksum = 0; // not used

				uint8_t *pkt_udp_payload = odp_packet_buf_addr(odp_pkt) + 20 + ODP_ETHHDR_LEN + ODP_IPV4HDR_LEN + ODP_UDPHDR_LEN;

				memcpy(pkt_udp_payload, odp_ipc_shm->in_p, udp_payload_len);

				printf("    odp: packet app -> odp -> out len %d // in_len queque: %d\n", 
						udp_payload_len, *odp_ipc_shm->out_len);
				odp_queue_enq(outq_def, odpbuf);
				//odp_buffer_free(odpbuf);
				*odp_ipc_shm->in_len = 0;
			} else {
				printf("%s() unable to alloc buf\n", __func__);
				sleep(1);
			}

			/* Print packet counts every once in a while */
			if (odp_unlikely(pkt_cnt++ % 1 == 0)) {
				printf("  [%02i] send pkt_cnt:%lu\n", thr, pkt_cnt);
				fflush(NULL);
			}
		}

		if (*odp_ipc_shm->out_len == 0) {
#if 1
			/* use schedule to get buf from any input queue */
			odpbuf = odp_schedule(NULL, ODP_SCHED_WAIT);
#else
			/* always dequeue from the same input queue */
			odpbuf = odp_queue_deq(inq_def);
			if (!odp_buffer_is_valid(odpbuf)) {
				continue;
			}
#endif
			odp_pkt = odp_packet_from_buffer(odpbuf);

			if (odp_packet_l4_offset(odp_pkt) == 0) {
				printf("not udp packet, check arp!\n");
				continue;
			}

			//odp_packet_print(odp_pkt);
			odp_udphdr_t *udp;

			udp = (odp_udphdr_t *)odp_packet_l4(odp_pkt);
			uint8_t *payload = (uint8_t*)udp + sizeof(odp_udphdr_t);
			int payload_len = odp_be_to_cpu_16(udp->length) - sizeof(odp_udphdr_t);

			if (payload_len > 1500) {
				printf("openvpn bug too big frames %d!!\n", odp_be_to_cpu_16(udp->length));
				odp_packet_print(odp_pkt);
				odp_buffer_free(odpbuf);
				continue;
			}

			memcpy(odp_ipc_shm->out_p, payload, payload_len);
			*odp_ipc_shm->out_len = payload_len;
#if 0
			{
				unsigned int b;
				printf("%s() read %d data from socket len %d:\n", __func__, *odp_ipc_shm->out_len,
						*odp_ipc_shm->out_len);
				for (b =0; b < 16; b++) {
					printf("%d:%x ",  b, *(volatile unsigned char *)(odp_ipc_shm->out_p + b));
				}
				printf("\n");
			}
#endif

			//odp_buffer_free(odpbuf);
			/* print packet counts every once in a while */
			if (odp_unlikely(pkt_cnt++ % 1 == 0)) {
				printf("  [%02i] recv pkt_cnt:%lu\n", thr, pkt_cnt);
				fflush(NULL);
			}
		}
	}
	return arg;
}

/**
 * ODP packet example main function
 */
int main(int argc, char *argv[])
{
	odp_linux_pthread_t thread_tbl[MAX_WORKERS];
	odp_buffer_pool_t pool;
	int thr_id;
	int num_workers;
	void *pool_base;
	int i;

	odp_ipc_shm = odp_ipc_shm_init();
	if (!odp_ipc_shm)
		return -1;

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


	/* Parse and store the application arguments */
	parse_args(argc, argv, &args->appl);

	/* get source mac addess */
	{
		int s;
		struct ifreq buffer;
		s = socket(PF_INET, SOCK_DGRAM, 0);
		memset(&buffer, 0x00, sizeof(buffer));
		strcpy(buffer.ifr_name, args->appl.if_names[0]);
		ioctl(s, SIOCGIFHWADDR, &buffer);
		close(s);
		memcpy(smac, buffer.ifr_hwaddr.sa_data, 6);
	}


	/* Print both system and application information */
	print_info(NO_PATH(argv[0]), &args->appl);

	num_workers = odp_sys_core_count();
	if (num_workers > MAX_WORKERS)
		num_workers = MAX_WORKERS;

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

	printf("\tSrc MAC: %hhx", smac[0]);
	for (i = 1; i < 6; i++)
		printf(":%hhx", smac[i]);
	printf("\n");
	printf("\tDst MAC: %hhx", dmac[0]);
	for (i = 1; i < 6; i++)
		printf(":%hhx", dmac[i]);
	printf("\n");
	printf("\tSrc IP: %x\n", sip);
	printf("\tDst IP: %x\n", dip);


	printf("\n\n odp_ipc daemon started on %s\n"
			"\t Run LD_PRELOAD ./odp_ldpreload.so app\n",
		args->appl.if_names[0]);

	/* Create and init worker threads */
	memset(thread_tbl, 0, sizeof(thread_tbl));
	for (i = 0; i < num_workers; ++i) {
		void *(*thr_run_func) (void *);
		int if_idx = i % args->appl.if_count;

		args->thread[i].pktio_dev = args->appl.if_names[if_idx];
		args->thread[i].pool = pool;
		args->thread[i].mode = args->appl.mode;

		thr_run_func = pktio_queue_send_thread;
		odp_linux_pthread_create(thread_tbl, 1, i, thr_run_func,
					 &args->thread[i]);
	}

	/* Master thread waits for other threads to exit */
	odp_linux_pthread_join(thread_tbl, num_workers);

	printf("Exit\n\n");

	return 0;
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
		{"mode", required_argument, NULL, 'm'},		/* return 'm' */
		{"dmac", required_argument, NULL, 'd'},		/* return 'd' */
		{"sip", required_argument, NULL, 's'},
		{"dip", required_argument, NULL, 'r'},
		{"help", no_argument, NULL, 'h'},		/* return 'h' */
		{NULL, 0, NULL, 0}
	};

	appl_args->mode = -1; /* Invalid, must be changed by parsing */

	while (1) {
		opt = getopt_long(argc, argv, "+i:d:p:s:r:h", longopts, &long_index);

		if (opt == -1)
			break;	/* No more options */

		switch (opt) {
			/* parse packet-io interface names */
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
		case 'd':
			i = sscanf(optarg, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &dmac[0], &dmac[1], &dmac[2], &dmac[3],
						&dmac[4], &dmac[5]);
			if (i != 6) {
				printf("unable to parse dmac %d\n", i);
				exit(-1);
			}
			break;
		case 's':
		case 'r':
			{
				struct hostent *he = gethostbyname(optarg);
				if (!he) {
					printf("unknown host %s\n", optarg);
					exit(-1);
				}
				if (opt == 's')
					memcpy(&sip, he->h_addr, he->h_length);
				else
					memcpy(&dip, he->h_addr, he->h_length);
			}
			break;

		case 'h':
			usage(argv[0]);
			exit(EXIT_SUCCESS);
			break;

		default:
			break;
		}
	}

	if (appl_args->if_count == 0) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
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
	       odp_sys_cache_line_size(), odp_sys_core_count()
	      );
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
	       "  E.g. %s -i eth0  -d 11:22:33:44:55:66 -s 195.0.0.1 -r 195.0.0.2\n"
	       "\n"
	       "OpenDataPlane example application.\n"
	       "\n"
	       "Mandatory OPTIONS:\n"
	       "  -i, --interface Eth interfaces (comma-separated, no spaces)\n"
	       "  -m, --mode      0: Burst send&receive packets (no queues)\n"
	       "                  1: Send&receive packets through ODP queues.\n"
	       " -d, --dmac	  remote mac address aa:bb:cc:dd:ee:ff\n"
	       " -s, --sip	  source IP address\n"
	       " -r, --dip	  destination IP address\n"
	       "\n"
	       "Optional OPTIONS\n"
	       "  -h, --help       Display help and exit.\n"
	       "\n", NO_PATH(progname), NO_PATH(progname)
	    );

}
