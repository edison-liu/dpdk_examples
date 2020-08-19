/*-
 *   BSD LICENSE
 *
 *   Copyright 2017 Mellanox.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Mellanox. nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/sysinfo.h>
#include <sys/mman.h>
#include <malloc.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <rte_eal.h>
#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_cycles.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_net.h>
#include <rte_flow.h>
#include <rte_malloc.h>


#define FLOW_PERF_BATCH 10000
#define RDTSC_TIME(start) \
		((rte_rdtsc() - start) / (float) rte_get_timer_hz())

static uint8_t port_id;
static uint16_t nr_queues = 4;
struct rte_mempool *mbuf_pool;
struct rte_flow *flow;
static struct rte_flow **perf_flows; /* Flows created. */
static struct rte_flow **perf_flows_random; /* Flows created. */
const char *dump_file = "/tmp/flowtest_dump";
int dump_flow_en;

#define ACTION_RAW_ENCAP_MAX_DATA 128
#define RAW_ENCAP_CONFS_MAX_NUM 8
struct sysinfo start_info;
struct sysinfo end_info;


/** Storage for struct rte_flow_action_raw_decap. */
struct raw_decap_conf {
	uint8_t data[ACTION_RAW_ENCAP_MAX_DATA];
	size_t size;
};
/** Storage for struct rte_flow_action_raw_encap. */
struct raw_encap_conf {
	uint8_t data[ACTION_RAW_ENCAP_MAX_DATA];
	uint8_t preserve[ACTION_RAW_ENCAP_MAX_DATA];
	size_t size;
};
struct raw_encap_conf raw_encap_confs[RAW_ENCAP_CONFS_MAX_NUM];
struct raw_decap_conf raw_decap_confs[RAW_ENCAP_CONFS_MAX_NUM];
struct flow_perf_stats {
	uint64_t created;
	uint64_t deleted;
};
struct flow_perf_stats stats = {0};
static uint64_t flow_per_round;
static uint64_t round_count = 1;
static uint64_t random_per_round = 300;
int force_quit;

static int
flow_stress_test(uint8_t port_id, struct rte_flow_error *error);

/* display usage */
static void
print_usage(const char *prgname)
{
	printf("%s [EAL options] -- -c count [-r round]\n"
	       "  -c count: flow number for each round\n"
	       "  -r round count: number of round (default is 1)\n"
	       "  -d dump file name: dump last round flow into file\n",
	       prgname);
}

/* Parse the argument given in the command line of the application */
static int
parse_args(int argc, char **argv)
{
	int opt, ret = 0;
	char **argvopt;
	int option_index;
	char *prgname = argv[0];
	static struct option lgopts[] = {
		{NULL, 0, 0, 0}
	};

	argvopt = argv;

	while ((opt = getopt_long(argc, argvopt, "c:r:dh",
				  lgopts, &option_index)) != EOF) {

		switch (opt) {
		case 'c':
			flow_per_round = strtoul(optarg, NULL, 0);
			if (flow_per_round <= 0)
				ret = -1;
			break;

		case 'r':
			round_count = strtoul(optarg, NULL, 0);
			if (round_count <= 0)
				ret = -1;
			break;
		case 'd':
			dump_flow_en = 1;
		case 'h':
			print_usage(prgname);
			rte_exit(EXIT_SUCCESS, "Displayed help\n");
			break;

		/* long options */
		case 0:
		default:
			print_usage(prgname);
			return -1;
		}
	}

	return ret;
}
/** Dump all flow rules. */
static int
port_flow_dump(uint16_t port_id, const char *file_name)
{
	int ret = 0;
	FILE *file = stdout;
	struct rte_flow_error error;

	if (file_name && strlen(file_name)) {
		file = fopen(file_name, "w");
		if (!file) {
			printf("Failed to create file %s: %s\n", file_name,
			       strerror(errno));
			return -errno;
		}
	}
	ret = rte_flow_dev_dump(port_id, file, &error);
	if (ret)
		printf("Failed to dump flow: %s\n", strerror(-ret));
	else
		printf("Flow dump finished\n");
	if (file_name && strlen(file_name))
		fclose(file);
	return ret;
}

static int
flow_stress_complete(void)
{
	/* closing and releasing resources */
	rte_eth_dev_stop(port_id);
	rte_eth_dev_close(port_id);

	return 0;
}

static void
init_port(void)
{
	int ret;
	uint16_t i;
	struct rte_eth_conf port_conf = {
		.rxmode = {
			.max_rx_pkt_len = ETHER_MAX_LEN, /**< Default maximum frame length. */
		},
		.txmode = {
			.offloads = DEV_TX_OFFLOAD_MBUF_FAST_FREE |
				    DEV_TX_OFFLOAD_MATCH_METADATA,
		},
	};

	printf("initializing port: %d\n", port_id);
	ret = rte_eth_dev_configure(port_id,
				nr_queues, nr_queues, &port_conf);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE,
			":: cannot configure device: err=%d, port=%u\n",
			ret, port_id);
	}

	for (i = 0; i < nr_queues; i++) {
		ret = rte_eth_rx_queue_setup(port_id, i, 512,
				     rte_eth_dev_socket_id(port_id),
				     NULL,
				     mbuf_pool);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
				":: Rx queue setup failed: err=%d, port=%u\n",
				ret, port_id);
		}
	}
	for (i = 0; i < nr_queues; i++) {
		ret = rte_eth_tx_queue_setup(port_id, i, 512,
				     rte_eth_dev_socket_id(port_id),
				     NULL);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
				":: Tx queue setup failed: err=%d, port=%u\n",
				ret, port_id);
		}
	}

	rte_eth_promiscuous_enable(port_id);
	ret = rte_eth_dev_start(port_id);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE,
			"rte_eth_dev_start:err=%d, port=%u\n",
			ret, port_id);
	}
}

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		force_quit = 1;
		printf("\nSignal %d received, preparing to exit...\n",
				signum);
		/* exit with the expected status */
		signal(signum, SIG_DFL);
		kill(getpid(), signum);
	}
}

static void
flow_perf_dump(const struct rte_flow_attr *attr,
	       const struct rte_flow_item patterns[] __rte_unused,
	       const struct rte_flow_action actions[] __rte_unused)
{

	printf("%s group %u, pattern: ", attr->ingress ? "ingress" : "egress",
	       attr->group);
	printf(" actions: ");
	printf("\n");
}

static int getMemValue(const char *str)
{
	FILE *file = fopen("/proc/self/status", "r");
	char line[255];
	int len = strlen(str);

	if (!file)
		return -1;
	while (fgets(line, 256, file) != NULL) {
		if (strncmp(line, str, len) == 0)
			printf("<====== %s\n", line);
	}
	fclose(file);
	return 0;
}

static int
flow_stress_test(uint8_t port, struct rte_flow_error *error)
{
	uint64_t start;
	uint64_t uport = 0;
	struct rte_flow *default_flow =  NULL;
	struct rte_flow *group_miss_flow = NULL;
	struct rte_flow *ingress_jump_flow = NULL;
	struct rte_flow *egress_jump_flow = NULL;
	uint32_t cnt = 0;

	struct rte_flow_attr attr = {
		.ingress = 1,
		.egress = 0,
		.group = 0,
	};
	struct _raw_encap_gre_ {
		struct rte_flow_item_eth eth;
		struct rte_flow_item_ipv4 ipv4;
		struct rte_flow_item_gre gre;
		struct rte_flow_item_gre_opt_key gre_key;
	} __rte_packed;
	struct _raw_encap_eth_ {
		struct rte_flow_item_eth eth;
	} __rte_packed;
	struct _raw_encap_gre_ raw_encap_gre = {
		.eth = {
			.src = {
				.addr_bytes = {0x10, 0x20, 0x30,
						0x40, 0x50, 0x60},
			},
			.dst = {
				.addr_bytes = {0xa0, 0xb0, 0xc0,
						0xd0, 0xe0, 0xf2},
			},
			.type = RTE_BE16(0x0800),
		},
		.ipv4 = {
			.hdr = {
				.src_addr = RTE_BE32(IPv4(10, 10, 0, 11)),
				.dst_addr = RTE_BE32(IPv4(10, 0, 0, 11)),
				.next_proto_id = 47,
				.version_ihl = 0x45,
				.time_to_live = 33,
			}
		},
		.gre = {
			.protocol = RTE_BE16(0x0800),
			.c_rsvd0_ver = RTE_BE16(0x2000),
		},
	};
	struct _raw_encap_eth_ raw_encap_eth = {
		.eth = {
			.src = {
				.addr_bytes = {0x10, 0x22, 0x33,
						0x44, 0x55, 0x60},
			},
			.dst = {
				.addr_bytes = {0xa0, 0xbb, 0xcc,
						0xdd, 0xee, 0xf2},
			},
			.type = RTE_BE16(0x0800),
		},
	};
	struct rte_flow_item_gre i_gre = {
		.protocol = RTE_BE16(ETHER_TYPE_IPv4),
	};
	struct rte_flow_item_gre_opt_key i_gre_key = {
		.key = RTE_BE32(0x1244f),
	};
	struct rte_flow_item *patterns = NULL;
	struct rte_flow_item *jump_patterns = NULL;
	struct rte_flow_action *actions = NULL;
	struct rte_flow_action jump_actions[2];
	struct rte_flow_item_ipv4 o_ip = {
		.hdr = {
			.src_addr = RTE_BE32(IPv4(10, 0, 0, 10)),
			.dst_addr = RTE_BE32(IPv4(10, 10, 0, 10)),
		}
	};
	struct rte_flow_item_ipv4 i_ipc = {
		.hdr = {
			.src_addr = RTE_BE32(IPv4(10, 0, 0, 10)),
			.dst_addr = RTE_BE32(IPv4(10, 10, 0, 10)),
		}
	};


	struct rte_flow_item_udp i_udp = {
		.hdr = {
			.src_port = RTE_BE16(3),
			.dst_port = RTE_BE16(4),
		},
	};
	struct rte_flow_item_udp i_udp_mask = {
		.hdr = {
			.src_port = RTE_BE16(0xFFFF),
			.dst_port = RTE_BE16(0xFFFF),
		},
	};

	struct rte_flow_action_mark mark = {
		.id = 0x123456
	};
	static struct rte_eth_rss_conf rss_conf = {
		.rss_key = NULL,
		.rss_key_len = 0,
		.rss_hf = ETH_RSS_IP,
		.rss_level = 0,
	};
	union {
		struct rte_flow_action_rss rss;
		struct {
			const struct rte_eth_rss_conf *rss_conf;
			uint16_t num;
			uint16_t queues[4];
		} local;
	} rss = {
		.local = {
			.rss_conf = &rss_conf,
			.num = 4,
			.queues = {0, 1, 2, 3},
		},
	};
	struct rte_flow_action_jump jump = {
		.group = 1,
	};
	jump_actions[0] = (struct rte_flow_action) {
		.type = RTE_FLOW_ACTION_TYPE_JUMP,
		.conf = &jump,
	};
	jump_actions[1] = (struct rte_flow_action) {
		.type = RTE_FLOW_ACTION_TYPE_END,
	};
	struct rte_flow_action_raw_encap encap_raw = {
		.data = NULL,
		.preserve = NULL,
		.size = raw_encap_confs[0].size,
	};
	struct rte_flow_action_raw_decap decap_raw = {
		.data = raw_decap_confs[1].data,
		.size = raw_decap_confs[1].size,
	};

	struct rte_flow_item_meta rmeta = {
		.data = RTE_BE32(8000000),
	};
	if (perf_flows) {
		printf("Flows overwritten\n");
		rte_free(perf_flows);
		perf_flows = NULL;
	}
	perf_flows = rte_malloc(NULL, sizeof(void *) * (flow_per_round + 1), 0);
	if (!perf_flows) {
		printf("Unable to allocate memory\n");
		return -1;
	}

	if (perf_flows_random) {
		printf("Flows overwritten\n");
		rte_free(perf_flows_random);
		perf_flows_random = NULL;
	}
	perf_flows_random = rte_malloc(NULL, sizeof(void *) * (random_per_round + 1), 0);
	if (!perf_flows_random) {
		printf("Unable to allocate memory\n");
		return -1;
	}

	printf("Creating...\n");
	getMemValue("VmRSS");
	fflush(stdout);

	/* default flow */
	attr.ingress = 1;
	attr.egress = 0;
	attr.priority = 1;
	attr.group = 0;
	patterns = (struct rte_flow_item[]) {
			{.type = RTE_FLOW_ITEM_TYPE_ETH},
			{.type = RTE_FLOW_ITEM_TYPE_IPV4},
			{.type = RTE_FLOW_ITEM_TYPE_GRE},
			{.type = RTE_FLOW_ITEM_TYPE_END},
	};
	actions = (struct rte_flow_action []) {
				{.type = RTE_FLOW_ACTION_TYPE_RSS,
				 .conf = &rss},
				{.type = RTE_FLOW_ACTION_TYPE_END},
	};
	default_flow =
		rte_flow_create(port, &attr, patterns,
					actions, error);
	if (!default_flow) {
		printf("Error create default flow:%s\n", error->message);
		return -1;
	}
	flow_perf_dump(&attr, patterns, actions);
	printf("1. Create default flow:%p\n", default_flow);


	i_ipc.hdr.src_addr = RTE_BE32(IPv4(192, 168, 0, 1));
	i_ipc.hdr.dst_addr = RTE_BE32(IPv4(192, 168, 10, 1));
	do {
		printf("######################### Flow create/flush testing, Round: %d #########################\n", ++cnt);
		o_ip.hdr.dst_addr = RTE_BE32(IPv4(10, 10, 0, 10));
		/* egress jump flow */
		attr.ingress = 0;
		attr.egress = 1;
		attr.group = 0;
		struct rte_flow_item_meta meta = {
			.data = RTE_BE32(0x1),
		};
		jump_patterns = (struct rte_flow_item[]) {
			{.type = RTE_FLOW_ITEM_TYPE_META,
			 .spec = &meta},
			{.type = RTE_FLOW_ITEM_TYPE_END},
		};
		egress_jump_flow =
			rte_flow_create(port, &attr, jump_patterns,
					jump_actions, error);
		if (!egress_jump_flow) {
			printf("Error create egress jump flow:%s\n",
					error->message);
			return -1;
		}
		flow_perf_dump(&attr, jump_patterns, jump_actions);
		printf("2. Create egress jump flow:%p\n", egress_jump_flow);

		stats.created++;
		if (!group_miss_flow) {
			/* group miss */
			patterns = (struct rte_flow_item[]) {
				{.type = RTE_FLOW_ITEM_TYPE_ETH},
				{.type = RTE_FLOW_ITEM_TYPE_IPV4},
				{.type = RTE_FLOW_ITEM_TYPE_GRE},
				{.type = RTE_FLOW_ITEM_TYPE_END},
			};
			actions = (struct rte_flow_action []) {
					{.type = RTE_FLOW_ACTION_TYPE_RSS,
					 .conf = &rss},
					{.type = RTE_FLOW_ACTION_TYPE_END},
			};
			attr.ingress = 1;
			attr.egress = 0;
			attr.priority = 1;
			attr.group = 1;
			group_miss_flow =
				rte_flow_create(port, &attr, patterns,
						actions, error);
			if (!group_miss_flow) {
				printf("Error create group miss flow:%s\n",
						error->message);
				return -1;
			}
			//	stats.created++;

			flow_perf_dump(&attr, patterns, actions);
			printf("3. Create ingress group miss flow:%p\n", group_miss_flow);
		}

		/* ingress jump flow */
		attr.ingress = 1;
		attr.egress = 0;
		attr.priority = 0;
		attr.group = 0;
		jump_patterns = (struct rte_flow_item[]) {
			{.type = RTE_FLOW_ITEM_TYPE_ETH},
			{.type = RTE_FLOW_ITEM_TYPE_IPV4,
			 .spec = &o_ip},
			{.type = RTE_FLOW_ITEM_TYPE_GRE},
			{.type = RTE_FLOW_ITEM_TYPE_END},
		};
		ingress_jump_flow =
			rte_flow_create(port, &attr, jump_patterns,
				jump_actions, error);
		if (!ingress_jump_flow) {
			printf("Error create ingress jump flow:%s\n",
					error->message);
			return -1;
		}
		stats.created++;
		printf("4. Create ingress group jump flow:%p\n", ingress_jump_flow);

		uint64_t i, idx;
		mark.id = 0x123456;
		o_ip.hdr.dst_addr = RTE_BE32(IPv4(10, 10, 0, 10));

		printf("5. Create test GRE flow:%p, %lu\n", perf_flows, flow_per_round);
		start = rte_rdtsc();
		for (i = 0, idx = 0; i < flow_per_round; ++i) {
			attr.group = 1;
			attr.priority = 0;
			if (i % 2 == 0) {
				/* ingress */
				attr.ingress = 1;
				attr.egress = 0;
				encap_raw.data = (uint8_t *)&raw_encap_eth;
				encap_raw.size = sizeof(raw_encap_eth);
				decap_raw.data = (uint8_t *)&raw_encap_gre;
				decap_raw.size = sizeof(raw_encap_gre);
				i_udp.hdr.src_port = RTE_BE16(uport >> 16);
				i_udp.hdr.dst_port = RTE_BE16(uport);
				uport++;
				patterns = (struct rte_flow_item[]) {
					{.type = RTE_FLOW_ITEM_TYPE_ETH},
					{.type = RTE_FLOW_ITEM_TYPE_IPV4},
					{.type = RTE_FLOW_ITEM_TYPE_GRE,
					 .spec = &i_gre,
					 .mask = &rte_flow_item_gre_mask},
					{.type = RTE_FLOW_ITEM_TYPE_GRE_OPT_KEY,
					 .spec = &i_gre_key,
					 .mask = &rte_flow_item_gre_opt_key_mask},
					{.type = RTE_FLOW_ITEM_TYPE_IPV4,
					 .spec = &i_ipc,
					 .mask = &rte_flow_item_ipv4_mask},
					{.type = RTE_FLOW_ITEM_TYPE_UDP,
					 .spec = &i_udp, .mask = &i_udp_mask},
					{.type = RTE_FLOW_ITEM_TYPE_END},
				};

				actions = (struct rte_flow_action []) {
					{.type = RTE_FLOW_ACTION_TYPE_MARK,
					 .conf = &mark},
					{.type = RTE_FLOW_ACTION_TYPE_RAW_DECAP,
					 .conf = &decap_raw},
					{.type = RTE_FLOW_ACTION_TYPE_RAW_ENCAP,
					 .conf = &encap_raw},
					{.type = RTE_FLOW_ACTION_TYPE_RSS,
					 .conf = &rss},
					{.type = RTE_FLOW_ACTION_TYPE_END},
				};

				perf_flows[idx] = rte_flow_create(port, &attr,
						patterns, actions, error);
				if (!perf_flows[idx++]) {
					printf("Error create flow [%"PRIu64"]\n",
						idx);
					return -1;
				}
				if (i == 0)
					flow_perf_dump(&attr,
						patterns, actions);
				stats.created++;
				mark.id++;
			} else {
					/* egress */
				attr.egress = 1;
				attr.ingress = 0;
				encap_raw.data = (uint8_t *)&raw_encap_gre;
				encap_raw.size = sizeof(raw_encap_gre);
				decap_raw.data = (uint8_t *)&raw_encap_eth;
				decap_raw.size = sizeof(raw_encap_eth);

				patterns = (struct rte_flow_item[]) {
					{.type = RTE_FLOW_ITEM_TYPE_META,
					 .spec = &meta},
					{.type = RTE_FLOW_ITEM_TYPE_END},
				};

				actions = (struct rte_flow_action []) {
					{.type = RTE_FLOW_ACTION_TYPE_RAW_DECAP,
					 .conf = &decap_raw},
					{.type = RTE_FLOW_ACTION_TYPE_RAW_ENCAP,
					 .conf = &encap_raw},
					{.type = RTE_FLOW_ACTION_TYPE_END},
				};
				perf_flows[idx] = rte_flow_create(port, &attr,
						patterns, actions, error);
				if (!perf_flows[idx++]) {
					printf("Error create flow [%"PRIu64"]:"
						"%s\n", idx, error->message);
					return -1;
				}
				if (i == 0)
					flow_perf_dump(&attr,
						patterns, actions);
				stats.created++;

				meta.data = rte_be_to_cpu_32(meta.data) + 1;
				meta.data = rte_be_to_cpu_32(meta.data);
			}
			if (force_quit)
				goto quit;
		}

		printf("Total %u, time: %f sec\n",
			(unsigned int)idx, RDTSC_TIME(start));

		printf("5. Create test random GRE flow:%p, %lu\n", perf_flows_random, random_per_round);
		start = rte_rdtsc();
		for (i = 0, idx = 0; i < random_per_round; ++i) {
			attr.group = 1;
			attr.priority = 0;
			/* egress */
			attr.egress = 1;
			attr.ingress = 0;
			encap_raw.data = (uint8_t *)&raw_encap_gre;
			encap_raw.size = sizeof(raw_encap_gre);
			decap_raw.data = (uint8_t *)&raw_encap_eth;
			decap_raw.size = sizeof(raw_encap_eth);

			patterns = (struct rte_flow_item[]) {
				{.type = RTE_FLOW_ITEM_TYPE_META,
				 .spec = &rmeta},
				{.type = RTE_FLOW_ITEM_TYPE_END},
			};

			actions = (struct rte_flow_action []) {
				{.type = RTE_FLOW_ACTION_TYPE_RAW_DECAP,
				 .conf = &decap_raw},
				{.type = RTE_FLOW_ACTION_TYPE_RAW_ENCAP,
				 .conf = &encap_raw},
				{.type = RTE_FLOW_ACTION_TYPE_END},
			};
			perf_flows_random[idx] = rte_flow_create(port, &attr,
					patterns, actions, error);
			if (!perf_flows_random[idx++]) {
				printf("Error create flow [%"PRIu64"]:"
					"%s\n", idx, error->message);
				return -1;
			}
			if (i == 0)
				flow_perf_dump(&attr,
					patterns, actions);
			stats.created++;

			rmeta.data = rte_be_to_cpu_32(rmeta.data) + 1;
			rmeta.data = rte_be_to_cpu_32(rmeta.data);
			if (force_quit)
				goto quit;
		}

quit:
		getMemValue("VmRSS");
		if (cnt == 1 && dump_flow_en)
			port_flow_dump(port, dump_file);
		printf("Destroying ....\n");
		printf("1. Destroy ingress jump flow:%p\n", ingress_jump_flow);
		if (rte_flow_destroy(port, ingress_jump_flow, error)) {
			printf("Error delete ingress jump flow:%s\n",
					error->message);
			return -1;
		}
		stats.deleted++;

		printf("2. Destroy egress jump flow:%p\n", egress_jump_flow);
		if (rte_flow_destroy(port, egress_jump_flow, error)) {
			printf("Error delete egress jump flow:%s\n",
					error->message);
			return -1;
		}
		stats.deleted++;

		printf("3. Destroy test GRE flow:%p\n", perf_flows);
		{
			struct rte_flow **flows = perf_flows;
			if (!flows)
				return -1;
			while (*flows) {
				if (rte_flow_destroy(port,
						*flows, error))
					printf("Error deleting flows\n");
				flows++;
				stats.deleted++;
			}
		}

		printf("3. Destroy test random flow:%p\n", perf_flows_random);
		{
			struct rte_flow **flows = perf_flows_random;
			if (!flows)
				return -1;
			while (*flows) {
				if (rte_flow_destroy(port,
						*flows, error))
					printf("Error deleting flows\n");
				flows++;
				stats.deleted++;
			}
		}
		printf("%s, send:%ld, del:%ld\n", __func__,
				stats.created, stats.deleted);
		malloc_trim(0);
		getMemValue("VmRSS");
		printf("########################################################################################\n");
	} while (--round_count && !force_quit);

	rte_free(perf_flows);
	perf_flows = NULL;

	rte_free(perf_flows_random);
	perf_flows_random = NULL;


	if (group_miss_flow) {
		printf("4. Destroy group miss flow:%p\n", group_miss_flow);
		if (rte_flow_destroy(port, group_miss_flow, error)) {
			printf("Error delete group miss flow:%s\n",
				error->message);
			return -1;
		}
		//stats.deleted++;
	}
	printf("5. Destroy default flow:%p\n", default_flow);
	if (rte_flow_destroy(port, default_flow, error)) {
		printf("Error delete default flow:%s\n",
				error->message);
		return -1;
	}

	return 0;
}

int
main(int argc, char **argv)
{
	int ret;
	uint8_t nr_ports;
	struct rte_flow_error error;

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	mallopt(M_MXFAST, 0);
	sysinfo(&start_info);
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "invalid EAL arguments\n");

	argc -= ret;
	argv += ret;
	/* parse application arguments (after the EAL ones) */
	ret = parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid arguments");

	nr_ports = rte_eth_dev_count();
	if (nr_ports == 0)
		rte_exit(EXIT_FAILURE, "no Ethernet ports found\n");
	port_id = 0;
	if (nr_ports != 1) {
		printf("warn: %d ports detected, but we use only one: port %u\n",
			nr_ports, port_id);
	}
	mbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", 4096, 128, 0,
					    RTE_MBUF_DEFAULT_BUF_SIZE,
					    rte_socket_id());
	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");

	init_port();

	/* create multiple flow */
	ret = flow_stress_test(port_id, &error);
	if (ret < 0) {
		printf("Flow can't be created %d message: %s\n",
			error.type,
			error.message ? error.message : "(no stated reason)");
		rte_exit(EXIT_FAILURE, "error in creating flow");
	}

	flow_stress_complete();

	return 0;
}


