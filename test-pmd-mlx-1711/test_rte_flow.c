/*-
 *   BSD LICENSE
 *
 *   Copyright 2016 6WIND S.A.
 *   Copyright 2016 Mellanox.
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
 *     * Neither the name of 6WIND S.A. nor the names of its
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

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_byteorder.h>
#include <cmdline_parse.h>
#include <cmdline_parse_etheraddr.h>
#include <cmdline_parse_string.h>
#include <cmdline_parse_num.h>
#include <rte_flow.h>
#include <rte_hexdump.h>

#include "testpmd.h"

/* */
#define FLOW_PERF_BATCH 10000
#define RDTSC_TIME(start) \
    ((rte_rdtsc() - start) / (float)rte_get_timer_hz())

static uint64_t nr_random_flows = 0;
//struct rte_flow *flow;
//static struct rte_flow **perf_flows; /* Flows created. */
//static struct rte_flow **perf_flows_random; /* Flows created. */

#define ACTION_RAW_ENCAP_MAX_DATA 128
#define RAW_ENCAP_CONFS_MAX_NUM 8

/** Storage for struct rte_flow_action_raw_decap. */
struct flow_raw_decap_conf
{
    uint8_t data[ACTION_RAW_ENCAP_MAX_DATA];
    size_t size;
};
/** Storage for struct rte_flow_action_raw_encap. */
struct flow_raw_encap_conf
{
    uint8_t data[ACTION_RAW_ENCAP_MAX_DATA];
    uint8_t preserve[ACTION_RAW_ENCAP_MAX_DATA];
    size_t size;
};
struct flow_raw_encap_conf flow_raw_encap_confs[RAW_ENCAP_CONFS_MAX_NUM];
struct flow_raw_decap_conf flow_raw_decap_confs[RAW_ENCAP_CONFS_MAX_NUM];

/* */
static void add_vlan_flow(void)
{
}

static void add_ip_flow(void)
{
}

static void add_icmp_flow(void)
{
}

static void add_udp_flow(void)
{
}

static void add_tcp_flow(void)
{
}

static void add_gre_flows_non_offload(void)
{
}

static void add_gre_flows_offload(void)
{
}

static int add_ingress_default_flow(uint8_t port, struct rte_flow_error *error)
{
    static struct rte_eth_rss_conf rss_conf = {
        .rss_key = NULL,
        .rss_key_len = 0,
        .rss_hf = ETH_RSS_IP,
        .rss_level = 0,
    };

    union
    {
        struct rte_flow_action_rss rss;
        struct
        {
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

	struct rte_flow *flow = NULL;

    struct rte_flow_attr attr = {
        .ingress = 1,
        .egress = 0,
        .group = 0,
        .priority = 1
    };

	struct rte_flow_item *patterns = NULL;
	struct rte_flow_action *actions = NULL;

    /* default flow */
    patterns = (struct rte_flow_item[]){
        {.type = RTE_FLOW_ITEM_TYPE_ETH},
        {.type = RTE_FLOW_ITEM_TYPE_IPV4},
        {.type = RTE_FLOW_ITEM_TYPE_GRE},
        {.type = RTE_FLOW_ITEM_TYPE_END},
    };
    actions = (struct rte_flow_action[]){
        {.type = RTE_FLOW_ACTION_TYPE_RSS,
         .conf = &rss},
        {.type = RTE_FLOW_ACTION_TYPE_END},
    };
    flow = rte_flow_create(port, &attr, patterns,
                        actions, error);
    if (!flow)
    {
        printf("Error create default flow:%s\n", error->message);
        return -1;
    }

	printf("Added ingress default flow for port %d\n", port);
	return 0;
}

static int add_egress_jump_flow(uint8_t port, struct rte_flow_error *error)
{
    struct rte_flow_action jump_actions[2];

    struct rte_flow_action_jump jump = {
        .group = 1,
    };
    jump_actions[0] = (struct rte_flow_action){
        .type = RTE_FLOW_ACTION_TYPE_JUMP,
        .conf = &jump,
    };
    jump_actions[1] = (struct rte_flow_action){
        .type = RTE_FLOW_ACTION_TYPE_END,
    };

    struct rte_flow_item_meta meta = {
        .data = RTE_BE32(0x1),
    };

	struct rte_flow *flow = NULL;
    struct rte_flow_attr attr = {
        .ingress = 0,
        .egress = 1,
        .group = 0,
        .priority = 0,
    };

    struct rte_flow_item *jump_patterns = NULL;

    /* egress jump flow */
    jump_patterns = (struct rte_flow_item[]){
        {.type = RTE_FLOW_ITEM_TYPE_META,
         .spec = &meta},
        {.type = RTE_FLOW_ITEM_TYPE_END},
    };
    flow = rte_flow_create(port, &attr, jump_patterns,
                        jump_actions, error);
    if (!flow)
    {
        printf("Error create egress jump flow:%s\n",
               error->message);
        return -1;
    }

	printf("Added egress jump flow for port %d\n", port);
	return 0;
}

static int add_ingress_miss_flow(uint8_t port, struct rte_flow_error *error)
{
    static struct rte_eth_rss_conf rss_conf = {
        .rss_key = NULL,
        .rss_key_len = 0,
        .rss_hf = ETH_RSS_IP,
        .rss_level = 0,
    };

    union
    {
        struct rte_flow_action_rss rss;
        struct
        {
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


	struct rte_flow *flow = NULL;

    struct rte_flow_attr attr = {
        .ingress = 1,
        .egress = 0,
        .group = 1,
        .priority = 1,
    };

	struct rte_flow_item *patterns = NULL;
	struct rte_flow_action *actions = NULL;

    patterns = (struct rte_flow_item[]){
        {.type = RTE_FLOW_ITEM_TYPE_ETH},
        {.type = RTE_FLOW_ITEM_TYPE_IPV4},
        {.type = RTE_FLOW_ITEM_TYPE_GRE},
        {.type = RTE_FLOW_ITEM_TYPE_END},
    };

    actions = (struct rte_flow_action[]){
        {.type = RTE_FLOW_ACTION_TYPE_RSS,
         .conf = &rss},
        {.type = RTE_FLOW_ACTION_TYPE_END},
    };

    flow = rte_flow_create(port, &attr, patterns,
                        actions, error);
    if (!flow)
    {
        printf("Error create group miss flow:%s\n",
               error->message);
        return -1;
    }

	printf("Added ingress miss flow for port %d\n", port);
	return 0;
}

static int add_ingress_jump_flow(uint8_t port, uint32_t sip, uint32_t dip, struct rte_flow_error *error)
{
	struct rte_flow_action jump_actions[2];

    struct rte_flow_item_ipv4 o_ip = {
        .hdr = {
            .src_addr = RTE_BE32(sip),
            .dst_addr = RTE_BE32(dip),
        }};

    struct rte_flow_action_jump jump = {
        .group = 1,
    };
    jump_actions[0] = (struct rte_flow_action){
        .type = RTE_FLOW_ACTION_TYPE_JUMP,
        .conf = &jump,
    };
    jump_actions[1] = (struct rte_flow_action){
        .type = RTE_FLOW_ACTION_TYPE_END,
    };

	struct rte_flow *flow = NULL;

    struct rte_flow_attr attr = {
        .ingress = 1,
        .egress = 0,
        .group = 0,
        .priority = 0,
    };

    struct rte_flow_item *jump_patterns = NULL;

    jump_patterns = (struct rte_flow_item[]){
        {.type = RTE_FLOW_ITEM_TYPE_ETH},
        {.type = RTE_FLOW_ITEM_TYPE_IPV4,
         .spec = &o_ip},
        {.type = RTE_FLOW_ITEM_TYPE_GRE},
        {.type = RTE_FLOW_ITEM_TYPE_END},
    };
		
    flow = rte_flow_create(port, &attr, jump_patterns,
                        jump_actions, error);
    if (!flow)
    {
        printf("Error create ingress jump flow:%s\n",
               error->message);
        return -1;
    }

	printf("Added ingress jump flow for port %d\n", port);
	return 0;
}

static int add_ingress_udp_flow(uint8_t port, uint32_t key, uint32_t in_sip, uint32_t in_dip, 
				uint16_t in_sport, uint16_t in_dport, uint32_t flow_mark,
				struct rte_flow_error *error)
{
	struct rte_flow *flow = NULL;

    struct rte_flow_action_raw_encap encap_raw = {
        .data = NULL,
        .preserve = NULL,
        .size = flow_raw_encap_confs[0].size,
    };
    struct rte_flow_action_raw_decap decap_raw = {
        .data = flow_raw_decap_confs[1].data,
        .size = flow_raw_decap_confs[1].size,
    };

    struct _raw_encap_gre_
    {
        struct rte_flow_item_eth eth;
        struct rte_flow_item_ipv4 ipv4;
        struct rte_flow_item_gre gre;
        struct rte_flow_item_gre_opt_key gre_key;
    } __rte_packed;
    struct _raw_encap_eth_
    {
        struct rte_flow_item_eth eth;
    } __rte_packed;
    struct _raw_encap_gre_ raw_encap_gre = {
        .eth = {
            .src = {
                .addr_bytes = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60},
            },
            .dst = {
                .addr_bytes = {0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf2},
            },
            .type = RTE_BE16(0x0800),
        },
        .ipv4 = {.hdr = {
                     .src_addr = RTE_BE32(IPv4(10, 10, 0, 11)),
                     .dst_addr = RTE_BE32(IPv4(10, 0, 0, 11)),
                     .next_proto_id = 47,
                     .version_ihl = 0x45,
                     .time_to_live = 33,
                 }},
        .gre = {
            .protocol = RTE_BE16(0x0800),
            .c_rsvd0_ver = RTE_BE16(0x2000),
        },
    };
    struct _raw_encap_eth_ raw_encap_eth = {
        .eth = {
            .src = {
                .addr_bytes = {0x10, 0x22, 0x33, 0x44, 0x55, 0x60},
            },
            .dst = {
                .addr_bytes = {0xa0, 0xbb, 0xcc, 0xdd, 0xee, 0xf2},
            },
            .type = RTE_BE16(0x0800),
        },
    };
    struct rte_flow_item_gre i_gre = {
        .protocol = RTE_BE16(ETHER_TYPE_IPv4),
    };
    struct rte_flow_item_gre_opt_key i_gre_key = {
        .key = key,
    };

    struct rte_flow_item_ipv4 i_ipc = {
        .hdr = {
            .src_addr = RTE_BE32(in_sip),
            .dst_addr = RTE_BE32(in_dip),
        }};

    struct rte_flow_item_udp i_udp = {
        .hdr = {
            .src_port = in_sport,
            .dst_port = in_dport,
        },
    };
    struct rte_flow_item_udp i_udp_mask = {
        .hdr = {
            .src_port = RTE_BE16(0xFFFF),
            .dst_port = RTE_BE16(0xFFFF),
        },
    };

    struct rte_flow_action_mark mark = {
        .id = flow_mark};
    static struct rte_eth_rss_conf rss_conf = {
        .rss_key = NULL,
        .rss_key_len = 0,
        .rss_hf = ETH_RSS_IP,
        .rss_level = 0,
    };
    union
    {
        struct rte_flow_action_rss rss;
        struct
        {
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

    struct rte_flow_attr attr = {
        .ingress = 1,
        .egress = 0,
        .group = 1,
        .priority = 0,
    };

	struct rte_flow_item *patterns = NULL;
	struct rte_flow_action *actions = NULL;

    encap_raw.data = (uint8_t *)&raw_encap_eth;
    encap_raw.size = sizeof(raw_encap_eth);
    decap_raw.data = (uint8_t *)&raw_encap_gre;
    decap_raw.size = sizeof(raw_encap_gre);
    i_udp.hdr.src_port = RTE_BE16(10000);
    i_udp.hdr.dst_port = RTE_BE16(20000);
    patterns = (struct rte_flow_item[]){
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
         .spec = &i_udp,
         .mask = &i_udp_mask},
        {.type = RTE_FLOW_ITEM_TYPE_END},
    };

    actions = (struct rte_flow_action[]){
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

    flow = rte_flow_create(port, &attr,
                           patterns, actions, error);
    if (!flow)
    {
        printf("Error create ingress group 1 flow for port %d\n", port);
        return -1;
    }

	printf("Added ingress UDP flow for port %d\n", port);
	return 0;
}

static int add_egress_encap_flow(uint8_t port, struct rte_flow_error *error)
{
    struct rte_flow_action_raw_encap encap_raw = {
        .data = NULL,
        .preserve = NULL,
        .size = flow_raw_encap_confs[0].size,
    };
    struct rte_flow_action_raw_decap decap_raw = {
        .data = flow_raw_decap_confs[1].data,
        .size = flow_raw_decap_confs[1].size,
    };

    struct _raw_encap_gre_
    {
        struct rte_flow_item_eth eth;
        struct rte_flow_item_ipv4 ipv4;
        struct rte_flow_item_gre gre;
        struct rte_flow_item_gre_opt_key gre_key;
    } __rte_packed;
    struct _raw_encap_eth_
    {
        struct rte_flow_item_eth eth;
    } __rte_packed;
    struct _raw_encap_gre_ raw_encap_gre = {
        .eth = {
            .src = {
                .addr_bytes = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60},
            },
            .dst = {
                .addr_bytes = {0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf2},
            },
            .type = RTE_BE16(0x0800),
        },
        .ipv4 = {.hdr = {
                     .src_addr = RTE_BE32(IPv4(10, 10, 0, 11)),
                     .dst_addr = RTE_BE32(IPv4(10, 0, 0, 11)),
                     .next_proto_id = 47,
                     .version_ihl = 0x45,
                     .time_to_live = 33,
                 }},
        .gre = {
            .protocol = RTE_BE16(0x0800),
            .c_rsvd0_ver = RTE_BE16(0x2000),
        },
    };
    struct _raw_encap_eth_ raw_encap_eth = {
        .eth = {
            .src = {
                .addr_bytes = {0x10, 0x22, 0x33, 0x44, 0x55, 0x60},
            },
            .dst = {
                .addr_bytes = {0xa0, 0xbb, 0xcc, 0xdd, 0xee, 0xf2},
            },
            .type = RTE_BE16(0x0800),
        },
    };

    struct rte_flow_item_meta meta = {
        .data = RTE_BE32(8000000),
    };

	struct rte_flow *flow = NULL;
	struct rte_flow_item *patterns = NULL;
	struct rte_flow_action *actions = NULL;

    struct rte_flow_attr attr = {
        .ingress = 0,
        .egress = 1,
        .group = 1,
        .priority = 0
    };

    encap_raw.data = (uint8_t *)&raw_encap_gre;
    encap_raw.size = sizeof(raw_encap_gre);
    decap_raw.data = (uint8_t *)&raw_encap_eth;
    decap_raw.size = sizeof(raw_encap_eth);

    patterns = (struct rte_flow_item[]){
        {.type = RTE_FLOW_ITEM_TYPE_META,
         .spec = &meta},
        {.type = RTE_FLOW_ITEM_TYPE_END},
    };

    actions = (struct rte_flow_action[]){
        {.type = RTE_FLOW_ACTION_TYPE_RAW_DECAP,
         .conf = &decap_raw},
        {.type = RTE_FLOW_ACTION_TYPE_RAW_ENCAP,
         .conf = &encap_raw},
        {.type = RTE_FLOW_ACTION_TYPE_END},
    };
    flow = rte_flow_create(port, &attr,
                           patterns, actions, error);
    if (!flow)
    {
        printf("Error create egress encap flow : %s\n", error->message);
        return -1;
    }

	printf("Created egress encap flow for port %d\n", port);
	return 0;
}

static int add_random_flow(uint8_t port, struct rte_flow_error *error)
{
    struct rte_flow_action_raw_encap encap_raw = {
        .data = NULL,
        .preserve = NULL,
        .size = flow_raw_encap_confs[0].size,
    };
    struct rte_flow_action_raw_decap decap_raw = {
        .data = flow_raw_decap_confs[1].data,
        .size = flow_raw_decap_confs[1].size,
    };

    struct _raw_encap_gre_
    {
        struct rte_flow_item_eth eth;
        struct rte_flow_item_ipv4 ipv4;
        struct rte_flow_item_gre gre;
        struct rte_flow_item_gre_opt_key gre_key;
    } __rte_packed;
    struct _raw_encap_eth_
    {
        struct rte_flow_item_eth eth;
    } __rte_packed;
    struct _raw_encap_gre_ raw_encap_gre = {
        .eth = {
            .src = {
                .addr_bytes = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60},
            },
            .dst = {
                .addr_bytes = {0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf2},
            },
            .type = RTE_BE16(0x0800),
        },
        .ipv4 = {.hdr = {
                     .src_addr = RTE_BE32(IPv4(10, 10, 0, 11)),
                     .dst_addr = RTE_BE32(IPv4(10, 0, 0, 11)),
                     .next_proto_id = 47,
                     .version_ihl = 0x45,
                     .time_to_live = 33,
                 }},
        .gre = {
            .protocol = RTE_BE16(0x0800),
            .c_rsvd0_ver = RTE_BE16(0x2000),
        },
    };
    struct _raw_encap_eth_ raw_encap_eth = {
        .eth = {
            .src = {
                .addr_bytes = {0x10, 0x22, 0x33, 0x44, 0x55, 0x60},
            },
            .dst = {
                .addr_bytes = {0xa0, 0xbb, 0xcc, 0xdd, 0xee, 0xf2},
            },
            .type = RTE_BE16(0x0800),
        },
    };

    struct rte_flow_item_meta rmeta = {
        .data = RTE_BE32(1000000),
    };

	struct rte_flow *flow = NULL;
	struct rte_flow_item *patterns = NULL;
	struct rte_flow_action *actions = NULL;

    struct rte_flow_attr attr = {
        .ingress = 0,
        .egress = 1,
        .group = 1,
        .priority = 0
    };

    unsigned int i;
    for (i = 0; i < nr_random_flows; ++i)
    {
        encap_raw.data = (uint8_t *)&raw_encap_gre;
        encap_raw.size = sizeof(raw_encap_gre);
        decap_raw.data = (uint8_t *)&raw_encap_eth;
        decap_raw.size = sizeof(raw_encap_eth);

        patterns = (struct rte_flow_item[]){
            {.type = RTE_FLOW_ITEM_TYPE_META,
             .spec = &rmeta},
            {.type = RTE_FLOW_ITEM_TYPE_END},
        };

        actions = (struct rte_flow_action[]){
            {.type = RTE_FLOW_ACTION_TYPE_RAW_DECAP,
             .conf = &decap_raw},
            {.type = RTE_FLOW_ACTION_TYPE_RAW_ENCAP,
             .conf = &encap_raw},
            {.type = RTE_FLOW_ACTION_TYPE_END},
        };
        flow = rte_flow_create(port, &attr,
                               patterns, actions, error);
        if (!flow)
        {
            printf("Error create random flow [%d]:"
                   "%s\n",
                   i, error->message);
            return -1;
        }

        rmeta.data = rte_be_to_cpu_32(rmeta.data) + 1;
        rmeta.data = rte_be_to_cpu_32(rmeta.data);
    }

	printf("Created test %lu random GRE flows for port %d\n", nr_random_flows, port);
	return 0;
}


/* */
static int add_simulated_flows(uint8_t port, struct rte_flow_error *error)
{
	add_ingress_default_flow(port, error);
	add_egress_jump_flow(port, error);
	add_ingress_miss_flow(port, error);
	add_ingress_jump_flow(port, IPv4(10, 10, 0, 1), IPv4(10, 10, 0, 2), error);
	add_ingress_udp_flow(port, RTE_BE32(1), IPv4(169, 254, 0, 47), IPv4(10, 0, 0, 7), 
		RTE_BE16(10000), RTE_BE16(20000), 123456, error);
	add_egress_encap_flow(port, error);
	//add_random_flow(port, error);

    return 0;
}

/* */
void add_rte_flows(portid_t pi)
{
    int ret = 0;
    struct rte_flow_error error;

    add_vlan_flow();
    add_ip_flow();
    add_icmp_flow();
    add_udp_flow();
    add_tcp_flow();
    add_gre_flows_non_offload();
    add_gre_flows_offload();

    /* create multiple flow */
    ret = add_simulated_flows(pi, &error);
    if (ret < 0)
    {
        printf("Flow can't be created %d message: %s\n",
               error.type,
               error.message ? error.message : "(no stated reason)");
        rte_exit(EXIT_FAILURE, "error in creating flow");
    }
}
