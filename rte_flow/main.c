#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <rte_lcore.h>
#include <rte_ethdev.h>
#include <rte_flow.h>
#include <rte_version.h>
#include <rte_thash.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PAL_RTE_LOG	"rte.log"
#define PAL_MAX_CPU	4
#define PAL_MAX_THREAD	4

#define __unused __attribute__((__unused__))

struct rss_tuple {
	uint32_t saddr;
	uint32_t daddr;
	uint16_t sport;
	uint16_t dport;
};

/* redirect rte_log */
static void pal_rte_log_init(const char *path)
{
	FILE *fp = fopen(path, "a");
	rte_openlog_stream(fp);
}

static void platform_init(void)
{
	int ret;
	int argc = 6;
	char arg0[] = "test-mlnx";
	char arg_cores[((PAL_MAX_CPU + 3) / 4) + sizeof("-c 0x")] = "-c 0x";
	char arg_memch[16] = "-n ";
	char arg_mem[] = "-m 4096";
        char b_pci[] = "-b 0000:af:00.0";
	char log_lvl[] = "--log-level=9";
	char *argv[] = {arg0, arg_cores, arg_memch, arg_mem, b_pci, log_lvl};
	int i, tid;
	unsigned bitmask;
	char hex2ascii[] = {"0123456789abcdef"};
	int cpus[PAL_MAX_CPU];
	int cpu;

	pal_rte_log_init(PAL_RTE_LOG);

	for (i = 0; i < PAL_MAX_CPU; i++)
		cpus[i] = 0;
	/* generate args for rte_eal_init "-c 0x** -n *" */
	for (tid = 0; tid < PAL_MAX_THREAD; tid++) {
		cpu = tid;
		cpus[cpu] = 1;
	}

	/* generate the args like "-c 0x1f" */
	arg_cores[sizeof(arg_cores) - 1] = 0;
	bitmask = 0;
	for (cpu = 0; cpu < PAL_MAX_CPU;) {
		if (cpus[cpu] == 1) {
			bitmask |= (1 << (cpu % 4));
		}
		if (++cpu % 4 != 0)
			continue;

		arg_cores[sizeof(arg_cores) - cpu / 4 - 1] = hex2ascii[bitmask];
		bitmask = 0;
	}
	if ((PAL_MAX_CPU % 4) != 0)
		arg_cores[sizeof(arg_cores) - PAL_MAX_CPU / 4 - 2] = hex2ascii[bitmask];

	/* generate the args like "-n 2" */
	snprintf(arg_memch + strlen(arg_memch),
	            sizeof(arg_memch) - strlen(arg_memch),
	            "%u", 3);

	/* Initialise eal */
	ret = rte_eal_init(argc, argv);
	if (ret < 0) {
		fprintf(stderr, "Cannot init EAL\n");
		abort();
	}
}

int rss_hash_symmetric = 0;
static uint8_t init_rkey[40] = {
	0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
	0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
	0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
	0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
};
#define MAX_RSS_KEY_LEN (40)

static int pal_gre_flow_add(int  port_id, int n_rxq)
{
	int  i;
	struct rte_flow_attr attr;
	struct rte_flow_item pattern[4];
	struct rte_flow_action actions[2];
	struct rte_flow_item_ipv4 ipmatch, ipmask;
	struct rte_flow_error error;
    	struct rte_flow *flow;
	uint16_t queue[RTE_MAX_QUEUES_PER_PORT];
	//uint8_t   n_rxq = pal_port_conf(port_id)->n_rxq;
	
	struct rte_flow_action_rss *rss = malloc( sizeof(*rss) + n_rxq * sizeof(uint16_t));
	if (rss == NULL) {
		rte_panic("malloc rss failed\n");
	}
	memset(&attr, 0, sizeof(attr));
	memset(&pattern, 0, sizeof(pattern));
	memset(&actions, 0, sizeof(actions));
	memset(&ipmatch, 0, sizeof(ipmatch));
	memset(&ipmask, 0, sizeof(ipmask));
	memset(&error, 0, sizeof(error));
	memset(rss, 0, sizeof(*rss) + n_rxq * sizeof(uint16_t));

	attr.ingress = 1;
	pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
	pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
	//proto gre
	ipmatch.hdr.next_proto_id = 47;
	ipmask.hdr.next_proto_id = 0xff;
	pattern[1].spec = &ipmatch;
	pattern[1].mask = &ipmask;
	pattern[2].type = RTE_FLOW_ITEM_TYPE_GRE;
	pattern[3].type = RTE_FLOW_ITEM_TYPE_END;
	actions[0].type = RTE_FLOW_ACTION_TYPE_RSS;
	actions[0].conf = rss;
	actions[1].type = RTE_FLOW_ACTION_TYPE_END;
	
	struct rte_eth_rss_conf *conf = malloc(sizeof(struct rte_eth_rss_conf));
	if (conf == NULL) {
		rte_panic("malloc rss failed\n");
	}
	memset((void *)conf, 0, sizeof(struct rte_eth_rss_conf));
	conf->rss_hf = ETH_RSS_IPV4 | ETH_RSS_FRAG_IPV4 |ETH_RSS_NONFRAG_IPV4_TCP | ETH_RSS_NONFRAG_IPV4_UDP;

	rss->func = RTE_ETH_HASH_FUNCTION_DEFAULT;
	rss->level = 2;
	rss->types = conf->rss_hf;
	rss->queue_num = n_rxq;
	
	if (rss_hash_symmetric) {
		rss->key_len = MAX_RSS_KEY_LEN;
		rss->key = init_rkey;
	}

	for (i = 0; i < n_rxq; i++) {
		queue[i] = i;
	}
        rss->queue = queue;

        flow = rte_flow_create(port_id, &attr, pattern, actions, &error);
	if (flow == NULL) {
		rte_panic("malloc rss failed\n");
	}

	union {
		struct rte_flow_query_count count;
	} query;

	int ret = rte_flow_query(0, flow, actions, &query, &error);
	if (!ret) {
		printf("query successs\n");
	} else {
		printf("query failed\n");
	}
	free(conf);
	free(rss);
	return 0;
}

static int pal_ip_flow_add(int  port_id, uint32_t ip, uint32_t ip_mask, int n_rxq)
{
	int i;
	struct rte_flow_attr attr;
	struct rte_flow_item pattern[4];
	struct rte_flow_action actions[2];
	struct rte_flow_item_ipv4 ipmatch, ipmask;
	struct rte_flow_error error;
	struct rte_flow *flow;
        uint16_t queue[RTE_MAX_QUEUES_PER_PORT];
	//uint8_t   n_rxq = pal_port_conf(port_id)->n_rxq;

	struct rte_flow_action_rss *rss = malloc(sizeof(*rss) + n_rxq * sizeof(uint16_t));
	if (rss == NULL)
		rte_panic("malloc rss failed\n");

	memset(&attr, 0, sizeof(attr));
	memset(&pattern, 0, sizeof(pattern));
	memset(&actions, 0, sizeof(actions));
	memset(&ipmatch, 0, sizeof(ipmatch));
	memset(&ipmask, 0, sizeof(ipmask));
	memset(&error, 0, sizeof(error));
	memset(rss, 0, sizeof(*rss) + n_rxq * sizeof(uint16_t));

	attr.ingress = 1;
	pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
	pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
    	ipmatch.hdr.dst_addr = ip;//0xcb3e10ac;
    	ipmask.hdr.dst_addr = ip_mask;
	pattern[1].spec = &ipmatch;
	pattern[1].mask = &ipmask;
	pattern[2].type = RTE_FLOW_ITEM_TYPE_END;
	actions[0].type = RTE_FLOW_ACTION_TYPE_RSS;
	actions[0].conf = rss;
	actions[1].type = RTE_FLOW_ACTION_TYPE_END;
	
	struct rte_eth_rss_conf *conf = malloc(sizeof(struct rte_eth_rss_conf));
	if (conf == NULL)
		rte_panic("malloc conf error\n");

	memset((void *)conf, 0, sizeof(struct rte_eth_rss_conf));
	conf->rss_hf = ETH_RSS_IPV4 | ETH_RSS_FRAG_IPV4 |ETH_RSS_NONFRAG_IPV4_TCP | ETH_RSS_NONFRAG_IPV4_UDP;
	rss->func = RTE_ETH_HASH_FUNCTION_DEFAULT;
	//rss->level = 2;
	rss->types = conf->rss_hf;
	rss->queue_num = n_rxq;
	
	if (rss_hash_symmetric) {
		rss->key_len = MAX_RSS_KEY_LEN;
		rss->key = init_rkey;
	}

        for (i = 0; i < n_rxq; i++) {
                queue[i] = i;
        }
        rss->queue = queue;

	if ((flow = rte_flow_create(port_id, &attr, pattern, actions, &error)) == NULL)
		rte_panic("create flow failed: %s\n", error.message);

	free(conf);
	free(rss);
	
	return 0;
}

static int pal_vlan_flow_add(int  port_id, uint16_t vlan_id, uint16_t vlan_mask,int n_rxq)
{
	int  i;
	struct rte_flow_attr attr;
	struct rte_flow_item pattern[4];
	struct rte_flow_action actions[2];
	struct rte_flow_item_vlan vlan, mask;
	struct rte_flow_error error;
	struct rte_flow *flow;
	//uint8_t   n_rxq = pal_port_conf(port_id)->n_rxq;
	uint16_t queue[RTE_MAX_QUEUES_PER_PORT];

	struct rte_flow_action_rss *rss = malloc(sizeof(*rss) + n_rxq * sizeof(uint16_t));
	if (rss == NULL)
		rte_panic("malloc rss failed\n");

	memset(&attr, 0, sizeof(attr));
	memset(&pattern, 0, sizeof(pattern));
	memset(&actions, 0, sizeof(actions));
	memset(&vlan, 0, sizeof(vlan));
	memset(&mask, 0, sizeof(mask));
	memset(&error, 0, sizeof(error));
	memset(rss, 0, sizeof(*rss) + n_rxq * sizeof(uint16_t));

	attr.ingress = 1;
	pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
	pattern[1].type = RTE_FLOW_ITEM_TYPE_VLAN;
    	vlan.tci  = htons(vlan_id);
    	mask.tci = htons(vlan_mask);
	pattern[1].spec = &vlan;
	pattern[1].mask = &mask;
	pattern[2].type = RTE_FLOW_ITEM_TYPE_END;
	actions[0].type = RTE_FLOW_ACTION_TYPE_RSS;
	actions[0].conf = rss;
	actions[1].type = RTE_FLOW_ACTION_TYPE_END;
	
	struct rte_eth_rss_conf *conf = malloc(sizeof(struct rte_eth_rss_conf));
	if (conf == NULL)
		rte_panic("malloc conf error\n");

	memset((void *)conf, 0, sizeof(struct rte_eth_rss_conf));
	conf->rss_hf = ETH_RSS_IPV4 | ETH_RSS_FRAG_IPV4 |ETH_RSS_NONFRAG_IPV4_TCP | ETH_RSS_NONFRAG_IPV4_UDP;
	rss->func = RTE_ETH_HASH_FUNCTION_DEFAULT;
	//rss->level = 2;
	rss->types = conf->rss_hf;
	rss->queue_num = n_rxq;
	
	if (rss_hash_symmetric) {
		rss->key_len = MAX_RSS_KEY_LEN;
		rss->key = init_rkey;
	}

        for (i = 0; i < n_rxq; i++) {
                queue[i] = i;
        }
        rss->queue = queue;

	if ((flow = rte_flow_create(port_id, &attr, pattern, actions, &error)) == NULL)
		rte_panic("create flow failed: %s\n", error.message);

	free(conf);
	free(rss);
	
	return 0;
}

static int pal_udp_flow_add(int  port_id,  uint32_t ip, uint32_t ip_mask, uint16_t port ,uint16_t port_mask,int n_rxq)
{
	int i;
	struct rte_flow_attr attr;
	struct rte_flow_item pattern[4];
	struct rte_flow_action actions[2];
	struct rte_flow_item_ipv4 ipmatch, ipmask;
    	struct rte_flow_item_udp udpmatch, udpmask;
	struct rte_flow_error error;
	struct rte_flow *flow;
    	//uint8_t   n_rxq = pal_port_conf(port_id)->n_rxq;
	uint16_t queue[RTE_MAX_QUEUES_PER_PORT];
	
	struct rte_flow_action_rss *rss = malloc(sizeof(*rss) + n_rxq * sizeof(uint16_t));
	if (rss == NULL)
		rte_panic("malloc rss failed\n");
	
	memset(&attr, 0, sizeof(attr));
	memset(&pattern, 0, sizeof(pattern));
	memset(&actions, 0, sizeof(actions));
	memset(&ipmatch, 0, sizeof(ipmatch));
	memset(&ipmask, 0, sizeof(ipmask));
    	memset(&udpmatch, 0, sizeof(udpmatch));
	memset(&udpmask, 0, sizeof(udpmask));
	memset(&error, 0, sizeof(error));
	memset(rss, 0, sizeof(*rss) + n_rxq * sizeof(uint16_t));
	
	attr.ingress = 1;
	pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
	pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
	ipmatch.hdr.next_proto_id = 17;
	ipmask.hdr.next_proto_id = 0xff;
	ipmatch.hdr.dst_addr = ip;//0xcb3e10ac;
    	ipmask.hdr.dst_addr = ip_mask;
	pattern[1].spec = &ipmatch;
	pattern[1].mask = &ipmask;
	pattern[2].type = RTE_FLOW_ITEM_TYPE_UDP;
	udpmatch.hdr.dst_port = htons(port);
	udpmask.hdr.dst_port  = htons(port_mask);
	pattern[2].spec = &udpmatch;
	pattern[2].mask = &udpmask;
	pattern[3].type = RTE_FLOW_ITEM_TYPE_END;
	actions[0].type = RTE_FLOW_ACTION_TYPE_RSS;
	actions[0].conf = rss;

	struct rte_eth_rss_conf *conf = malloc(sizeof(struct rte_eth_rss_conf));
	if (conf == NULL)
		rte_panic("malloc conf error\n");
	memset((void *)conf, 0, sizeof(struct rte_eth_rss_conf));
	conf->rss_hf = ETH_RSS_IPV4 | ETH_RSS_FRAG_IPV4 | ETH_RSS_NONFRAG_IPV4_TCP | ETH_RSS_NONFRAG_IPV4_UDP;
	//rss->level = 1;
	rss->types = conf->rss_hf;
	rss->queue_num = n_rxq;
	
	if (rss_hash_symmetric) {
		rss->key_len = MAX_RSS_KEY_LEN;
		rss->key = init_rkey;
	}

        for (i = 0; i < n_rxq; i++) {
                queue[i] = i;
        }
        rss->queue = queue;

	if ((flow = rte_flow_create(port_id, &attr, pattern, actions, &error)) == NULL)
		rte_panic("create flow failed: %s\n", error.message);

	free(conf);
	free(rss);

	return 0;
}

static int port_rxtx_init(unsigned port_id, unsigned n_rxq, unsigned n_txq)
{
	int ret;
	unsigned rxq, txq;
	char name[RTE_RING_NAMESIZE];
	struct rte_mempool *pktmbuf_pool;
	struct rte_eth_txconf tx_conf = {
		.tx_thresh = {
			.pthresh = 36,  /* Ring prefetch threshold */
			.hthresh = 0,   /* Ring host threshold */
			.wthresh = 0,   /* Ring writeback threshold */
		},
		.tx_free_thresh = 0,    /* Use PMD default values */
		.tx_rs_thresh = 0,      /* Use PMD default values */
		.offloads =
			DEV_TX_OFFLOAD_GRE_TNL_TSO |
			DEV_TX_OFFLOAD_OUTER_IPV4_CKSUM |
			DEV_TX_OFFLOAD_IPV4_CKSUM |
			DEV_TX_OFFLOAD_UDP_CKSUM |
			DEV_TX_OFFLOAD_TCP_CKSUM |
			DEV_TX_OFFLOAD_TCP_TSO |
			DEV_TX_OFFLOAD_MULTI_SEGS,
	};
	struct rte_eth_rxconf rx_conf = {
		.rx_thresh = {
			.pthresh = 8,   /* Ring prefetch threshold */
			.hthresh = 8,   /* Ring host threshold */
			.wthresh = 4,   /* Ring writeback threshold */
		},
		.rx_free_thresh = 32,    /* Immediately free RX descriptors */
		.rx_drop_en = 1,
	};

	for (rxq = 0; rxq < n_rxq; rxq++) {
		snprintf(name, RTE_RING_NAMESIZE, "port_%u_pool_%u", port_id, rxq);
		pktmbuf_pool = rte_mempool_create(name, 40000, 2256,
			64, sizeof(struct rte_pktmbuf_pool_private),
			rte_pktmbuf_pool_init, NULL, rte_pktmbuf_init,
			NULL, 0, MEMPOOL_F_SC_GET);
		if (pktmbuf_pool == NULL) {
			printf("Could not initialise mbuf pool %u\n", rxq);
			abort();
		}

		ret = rte_eth_rx_queue_setup(port_id, rxq, 2048,
			0, &rx_conf, pktmbuf_pool);
		if (ret < 0) {
			fprintf(stderr, "rxq setup error\n");
			abort();
		}
	}

	for (txq = 0; txq < n_txq; txq++) {
		ret = rte_eth_tx_queue_setup(port_id, txq, 2048,
		                      rte_eth_dev_socket_id(port_id), &tx_conf);
		if (ret < 0) {
			printf("Could not setup up TX queue %u for "
			              "port%u (%d)\n", txq, port_id, ret);
		}
	}

	return 0;
}

/*
 *  * link-status-changing(LSC) callback
 *   */
static int lsc_callback(uint16_t port_id, enum rte_eth_event_type type,
        __unused void *param, __unused void *ret_param)
{
        struct rte_eth_link link;

        if (type == RTE_ETH_EVENT_INTR_LSC) {
                printf("LSC Port:%u Link status changed\n", port_id);
                rte_eth_link_get(port_id, &link);
                if (link.link_status) {
                        printf("LSC Port:%u Link Up - speed %u Mbps - %s\n",
                                port_id, (unsigned)link.link_speed,
                                (link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
                                ("full-duplex") : ("half-duplex"));
                } else {
                        printf("LSC Port:%u Link Down\n", port_id);
                }
        }

        return 0;
}

static int flow_isolate(unsigned port_id)
{
        return rte_flow_isolate(port_id, 1, NULL);
}


static int port_init(void)
{
	int ret;
	struct rte_eth_conf port_conf;

	memset(&port_conf, 0, sizeof(port_conf));
	port_conf.rxmode.mq_mode = ETH_MQ_RX_RSS;
	port_conf.txmode.mq_mode = ETH_MQ_TX_NONE;
	port_conf.rx_adv_conf.rss_conf.rss_hf = ETH_RSS_IPV4 | ETH_RSS_NONFRAG_IPV4_TCP | \
	                                        ETH_RSS_NONFRAG_IPV4_UDP;
	port_conf.fdir_conf.mode = RTE_FDIR_MODE_PERFECT;
	port_conf.intr_conf.lsc = 1;
	port_conf.txmode.offloads = 
				DEV_TX_OFFLOAD_GRE_TNL_TSO |
				DEV_TX_OFFLOAD_OUTER_IPV4_CKSUM |
				DEV_TX_OFFLOAD_IPV4_CKSUM |
				DEV_TX_OFFLOAD_UDP_CKSUM |
				DEV_TX_OFFLOAD_TCP_CKSUM |
				DEV_TX_OFFLOAD_TCP_TSO |
				DEV_TX_OFFLOAD_MULTI_SEGS;

	ret = rte_eth_dev_configure(0, 8, 8, &port_conf);
	if (ret < 0) {
		fprintf(stderr, "Could not configure port\n");
		abort();
	}

	rte_eth_dev_callback_register(0, RTE_ETH_EVENT_INTR_LSC, lsc_callback, NULL);

	port_rxtx_init(0, 8, 8);
	ret = pal_gre_flow_add(0, 8);
	if (ret < 0) {
		fprintf(stderr, "flow init error\n");
		abort();
	}

	//session sync unicast
	//static int pal_ip_flow_add(int  port_id, uint32_t ip, uint32_t ip_mask, int n_rxq)
//	ret = pal_ip_flow_add(0, 8, 0xcb3e10ac,RTE_BE16(1000),8);
	ret = pal_ip_flow_add(0, 0x2fe71e10,0xffffffff,8);
	if (ret < 0) {
		fprintf(stderr, "flow init error\n");
		abort();
	}
//	static int pal_vlan_flow_add(int  port_id, uint16_t vlan_id, uint16_t vlan_mask,int n_rxq)
        ret = pal_vlan_flow_add(0, 100,0xffff,8);
        if (ret < 0) {
                fprintf(stderr, "flow init error\n");
                abort();
        }
//	int pal_udp_flow_add(int  port_id,  uint32_t ip, uint32_t ip_mask, uint16_t port ,uint16_t port_mask,int n_rxq)
	ret = pal_udp_flow_add(0, 0x2fe71e09,0xffffffff,100,0xff00, 8);
        if (ret < 0) {
                fprintf(stderr, "flow init error\n");
                abort();
        }
	ret = flow_isolate(0);
	if (ret < 0) {
		fprintf(stderr, "flow isolate error\n");
		abort();
	}

	ret = rte_eth_dev_start(0);
	if (ret < 0) {
		fprintf(stderr, "start error\n");
		abort();
	}

	printf("rte_eth_dev_start\n");
	rte_eth_promiscuous_enable(0);

	return 0;
}

static uint32_t get_rss(struct rss_tuple *tuple, uint32_t len)
{
	int ret;
	struct rte_eth_rss_conf rss_conf;
	rss_conf.rss_key = malloc(40);
	uint8_t new_key[40];
	uint32_t key;

	ret = rte_eth_dev_rss_hash_conf_get(0, &rss_conf);
	if (ret != 0) {
		printf("get port rss conf error\n");
		return 0;
	}

	
	rte_convert_rss_key((const uint32_t *)rss_conf.rss_key, (uint32_t *)new_key, 40);
	key = rte_softrss_be((void *)tuple, len, new_key);
	if (rss_conf.rss_key != NULL)
		free(rss_conf.rss_key);

	return key;
}

int
main(void)
{
	int i, j;
	int n_rx;
	uint32_t *sip, *dip;
	struct rte_mbuf *skbs[64];
	struct rss_tuple tuple;

	platform_init();

	port_init();

	while (1) {
		for (i = 0; i < 8; i++) {
			n_rx = rte_eth_rx_burst(0, i, skbs, 16);
			for (j = 0; j < n_rx; j++) {
				sip = (uint32_t *)((uint8_t *)skbs[j]->buf_addr + skbs[j]->data_off + 50);
				dip = (uint32_t *)((uint8_t *)skbs[j]->buf_addr + skbs[j]->data_off + 54);
				tuple.saddr = ntohl(*sip);
				tuple.daddr = ntohl(*dip);
				uint32_t rss = get_rss(&tuple, 8);
				printf("-------sip: %x, dip: %x-------\n", *sip, *dip);
				printf("hash: %x\n", skbs[j]->hash.rss);
				printf("soft hash: %x\n", rss);
				rte_pktmbuf_free(skbs[j]);
			}
		}
	}

	return 0;
}
