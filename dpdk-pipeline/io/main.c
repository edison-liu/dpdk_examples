
#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/queue.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>

#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_log.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_ring.h>
#include <rte_launch.h>
#include <rte_debug.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_interrupts.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_string_fns.h>

#define RTE_LOGTYPE_APP RTE_LOGTYPE_USER1

#define PARAM_FUNC              "func"
#define PARAM_INGRESS_PORT      "ingress-port"
#define PARAM_INGRESS_QUEUE     "ingress-queue"
#define PARAM_EGRESS_RING       "egress-ring"
#define PARAM_INGRESS_RING      "ingress-ring"
#define PARAM_EGRESS_PORT       "egress-port"
#define PARAM_EGRESS_QUEUE      "egress-queue"


/* Number of packets to attempt to read from queue */
#define PKT_READ_SIZE  ((uint16_t)64)

#define MBQ_CAPACITY 64

#define PKT_BURST 64

/*
 * Shared port info, including statistics information for display by server.
 * Structure will be put in a memzone.
 * - All port id values share one cache line as this data will be read-only
 * during operation.
 * - All rx statistic values share cache lines, as this data is written only
 * by the server process. (rare reads by stats display)
 * - The tx statistics have values for all ports per cache line, but the stats
 * themselves are written by the clients, so we have a distinct set, on different
 * cache lines for each client to use.
 */
struct rx_stats{
	uint64_t rx[RTE_MAX_ETHPORTS];
} __rte_cache_aligned;

struct tx_stats{
	uint64_t tx[RTE_MAX_ETHPORTS];
	uint64_t tx_drop[RTE_MAX_ETHPORTS];
} __rte_cache_aligned;

/*
 * Local buffers to put packets in, used to send packets in bursts to the
 * clients
 */
struct client_rx_buf {
	struct rte_mbuf *buffer[PKT_READ_SIZE];
	uint16_t count;
};

enum {
    FUNC_RX = 1,
    FUNC_TX = 2,
} FUNC_MODE;

/* maps input ports to output ports for packets */
static uint16_t output_ports[RTE_MAX_ETHPORTS];

/* buffers up a set of packet that are ready to send */
struct rte_eth_dev_tx_buffer *tx_buffer[RTE_MAX_ETHPORTS];

/* shared data from server. We update statistics here */
static volatile struct tx_stats g_tx_stats[RTE_MAX_ETHPORTS];

/* One buffer per client rx queue - dynamically allocate array */
static struct client_rx_buf *cl_rx_buf;

static uint16_t g_func = -1;
static uint32_t g_port_id = -1;
static uint32_t g_queue_id = -1;
static char *g_egress_ring = NULL;
static char *g_ingress_ring = NULL;

/*
 * print a usage message
 */
static void
usage(const char *progname, const char *errmsg)
{
	printf("\nError: %s\n",errmsg);
	printf("\n%s [EAL options] --"
			"--"PARAM_FUNC" <rx | tx>\n"
            "--"PARAM_INGRESS_PORT" <port>\n"
            "--"PARAM_INGRESS_QUEUE" <queue>\n"
            "--"PARAM_EGRESS_RING" <ring>\n"
            "--"PARAM_INGRESS_RING" <ring>\n"
            "--"PARAM_EGRESS_PORT" <port>\n"
            "--"PARAM_EGRESS_QUEUE" <queue>\n"
			"\n",
			progname);
	exit(1);
}

static int
parse_func(const char *str)
{
	if (strncmp(str, "rx", 2) == 0) {
        g_func = FUNC_RX;
        return 0;
        
    } else if (strncmp(str, "tx", 2) == 0) {
        g_func = FUNC_TX;
        return 0;
    }

	return -1;
}

/*
 * Parse the application arguments to the client app.
 */
static int
parse_app_args(int argc, char *argv[])
{
	int opt, ret;
	char **argvopt;
	int option_index;
	uint16_t i, port_mask = 0;
	char *prgname = argv[0];
	static struct option lgopts[] = {
			{PARAM_FUNC, 1, 0, 0},
			{PARAM_INGRESS_PORT, 1, 0, 0},
            {PARAM_INGRESS_QUEUE, 1, 0, 0},
            {PARAM_EGRESS_RING, 1, 0, 0},
            {PARAM_INGRESS_RING, 1, 0, 0},
            {PARAM_EGRESS_PORT, 1, 0, 0},
            {PARAM_EGRESS_QUEUE, 1, 0, 0},
			{NULL, 0, 0, 0}
	};

	argvopt = argv;

	while ((opt = getopt_long(argc, argvopt, "", \
			lgopts, &option_index)) != EOF) {

		switch (opt) {
			/* long options */
		case 0:
			if (strncmp(lgopts[option_index].name, PARAM_FUNC, 2) == 0) {
                if (parse_func(optarg) < 0) {
                    usage(prgname, "invalid func\n");
                    return -1;
                }
            }
			else if (strncmp(lgopts[option_index].name, PARAM_INGRESS_PORT, 12) == 0) {
                g_port_id = atoi(optarg);
            } else if (strncmp(lgopts[option_index].name, PARAM_INGRESS_PORT, 12) == 0) {
                g_port_id = atoi(optarg);
            } else if (strncmp(lgopts[option_index].name, PARAM_INGRESS_QUEUE, 13) == 0) {
                g_queue_id = atoi(optarg);
            } else if (strncmp(lgopts[option_index].name, PARAM_EGRESS_RING, 11) == 0) {
                g_egress_ring = optarg;
            } else if (strncmp(lgopts[option_index].name, PARAM_INGRESS_RING, 12) == 0) {
                g_ingress_ring = optarg;
            } else if (strncmp(lgopts[option_index].name, PARAM_EGRESS_PORT, 11) == 0) {
                g_port_id = atoi(optarg);
            } else if (strncmp(lgopts[option_index].name, PARAM_EGRESS_QUEUE, 12) == 0) {
                g_queue_id = atoi(optarg);
            } 
				
			break;

		default:
			usage(prgname, "Cannot parse all command-line arguments\n");
		}
	}

	if (optind >= 0)
		argv[optind-1] = prgname;

	if (g_port_id < 0)
		usage(prgname, "Invalid or missing proc-id parameter\n");

	ret = optind-1;
	optind = 1; /* reset getopt lib */

	return ret;
}

/*
 * Given the rx queue name template above, get the queue name
 */
static inline const char *
get_tx_queue_name(unsigned id)
{
	//return "ring:tx:0:0";
	static char buffer[32];

	snprintf(buffer, sizeof(buffer), "ring:tx:%d:%d", g_port_id, g_queue_id);
	return buffer;
}

static inline const char *
get_rx_queue_name(unsigned id)
{
	static char buffer[32];

	snprintf(buffer, sizeof(buffer), "ring:tx:%d:%d", g_port_id, g_queue_id);
	return buffer;
}

static inline const char *
get_mbuf_pool_name(unsigned id)
{
	//return "mbuf_pool_socket_0";
	static char buffer[32];

	snprintf(buffer, sizeof(buffer), "mbuf_pool_socket_%d", id);
	return buffer;
}

/*
 * Tx buffer error callback
 */
static void
flush_tx_error_callback(struct rte_mbuf **unsent, uint16_t count,
		void *userdata) {
	int i;
	uint16_t port_id = (uintptr_t)userdata;

	g_tx_stats->tx_drop[port_id] += count;

	/* free the mbufs which failed from transmit */
	for (i = 0; i < count; i++)
		rte_pktmbuf_free(unsent[i]);

}

static void
configure_tx_buffer(uint16_t port_id, uint16_t size)
{
	int ret;

	/* Initialize TX buffers */
	tx_buffer[port_id] = rte_zmalloc_socket("tx_buffer",
			RTE_ETH_TX_BUFFER_SIZE(size), 0,
			rte_eth_dev_socket_id(port_id));
	if (tx_buffer[port_id] == NULL)
		rte_exit(EXIT_FAILURE, "Cannot allocate buffer for tx on port %u\n",
			 port_id);

	rte_eth_tx_buffer_init(tx_buffer[port_id], size);

	ret = rte_eth_tx_buffer_set_err_callback(tx_buffer[port_id],
			flush_tx_error_callback, (void *)(intptr_t)port_id);
	if (ret < 0)
		rte_exit(EXIT_FAILURE,
		"Cannot set error callback for tx buffer on port %u\n",
			 port_id);
}

/*
 * set up output ports so that all traffic on port gets sent out
 * its paired port. Index using actual port numbers since that is
 * what comes in the mbuf structure.
 */
static void
configure_output_ports()
{
    configure_tx_buffer(0, MBQ_CAPACITY);
    configure_tx_buffer(1, MBQ_CAPACITY);
}

/*
 * This function performs routing of packets
 * Just sends each input packet out an output port based solely on the input
 * port it arrived on.
 */
static void
handle_tx_packet(struct rte_mbuf *buf)
{
	int sent;

	struct rte_eth_dev_tx_buffer *buffer = tx_buffer[g_port_id];

	sent = rte_eth_tx_buffer(g_port_id, g_queue_id, buffer, buf);
	if (sent)
		g_tx_stats->tx[g_port_id] += sent;
}

/*
 * send a burst of traffic to a client, assuming there are packets
 * available to be sent to this client
 */
static void
flush_rx_queue(uint16_t client)
{
	uint16_t j;

	if (cl_rx_buf[client].count == 0)
		return;

	if (rte_ring_enqueue_bulk(g_egress_ring, (void **)cl_rx_buf[client].buffer, cl_rx_buf[client].count, NULL) == 0){
		for (j = 0; j < cl_rx_buf[client].count; j++)
			rte_pktmbuf_free(cl_rx_buf[client].buffer[j]);
	}

	cl_rx_buf[client].count = 0;
}

/*
 * marks a packet down to be sent to a particular client process
 */
static inline void
enqueue_rx_packet(uint8_t client, struct rte_mbuf *buf)
{
	cl_rx_buf[client].buffer[cl_rx_buf[client].count++] = buf;
}

/*
 * This function takes a group of packets and routes them
 * individually to the client process. Very simply round-robins the packets
 * without checking any of the packet contents.
 */
static void
process_rx_packets(uint32_t port_num __rte_unused,
		struct rte_mbuf *pkts[], uint16_t rx_count)
{
	uint16_t i;
	uint8_t client = 0;

	for (i = 0; i < rx_count; i++) {
		enqueue_rx_packet(client, pkts[i]);
	}

	flush_rx_queue(0);
}

static void do_rx()
{
    const unsigned id = rte_lcore_id();
    printf("rx: lcore %u using port %d queue %u\n", id, g_port_id, (unsigned)g_queue_id);
    
	struct rte_ring *rx_ring;    
	int need_flush = 0; /* indicates whether we have unsent packets */
	void *pkts[PKT_READ_SIZE];
	uint16_t sent;

	rx_ring = rte_ring_lookup(get_rx_queue_name(0));
	if (rx_ring == NULL)
		rte_exit(EXIT_FAILURE, "Cannot get RX ring - is server process running?\n");

	for (;;) {
		struct rte_mbuf *buf[PKT_READ_SIZE];
		uint16_t rx_count, nb_tx;

		/* read a port */
		rx_count = rte_eth_rx_burst(g_port_id, g_queue_id, buf, PKT_BURST);
        if (unlikely(rx_count == 0))
            continue;

        /* Now process the NIC packets read */
        int nb_enqd = rte_ring_enqueue_burst(rx_ring, (void **) buf, rx_count, NULL);
        if (nb_enqd < rx_count) {
            printf("Failed to enqueue %d packets, actually %d done\n", rx_count, nb_enqd);
        }

        //nb_tx = rte_eth_tx_burst(g_port_id, g_queue_id,
        //        buf, rx_count);

        //printf("Enqueue packets %d\n", nb_enqd);
        //process_rx_packets(g_port_id, buf, rx_count);
        
        //int i;
        //for (i = 0; i < rx_count; i++)
        //    rte_pktmbuf_free(buf[i]);

	}
}

static void do_tx()
{
    int drain_flag = 0;
    const unsigned id = rte_lcore_id();
    printf("tx: lcore %u ingress %s using port %d queue %u\n", id, g_ingress_ring, g_port_id, (unsigned)g_queue_id);

	struct rte_ring *rx_ring;    
	int need_flush = 0; /* indicates whether we have unsent packets */
	void *pkts[PKT_READ_SIZE];
	uint16_t sent;

	rx_ring = rte_ring_lookup(get_rx_queue_name(0));
	if (rx_ring == NULL)
		rte_exit(EXIT_FAILURE, "Cannot get RX ring - is server process running?\n");

	for (;;) {
		uint16_t i, rx_pkts, nb_tx, retry;

		rx_pkts = rte_ring_dequeue_burst(rx_ring, pkts,
				PKT_READ_SIZE, NULL);
        if (unlikely(rx_pkts == 0)) {
            if (drain_flag == 0) {
                printf("Ring %s is drained\n", g_ingress_ring);
                drain_flag = 1;
            }
            continue;
        }

        if (drain_flag == 0) {
            int i;
            for (i = 0; i < rx_pkts; i++)
                rte_pktmbuf_free(pkts[i]);
            continue;
        }

        //printf("Received packets %d\n", rx_pkts);
        nb_tx = rte_eth_tx_burst(g_port_id, g_queue_id,
                pkts, rx_pkts);
        /*
         * Retry if necessary
         */
        if (unlikely(nb_tx < rx_pkts)) {
            retry = 0;
            while (nb_tx < rx_pkts && retry++ < 3) {
                rte_delay_us(1);
                nb_tx += rte_eth_tx_burst(g_port_id, g_queue_id,
                        &pkts[nb_tx], rx_pkts - nb_tx);
            }
        }

        if (unlikely(nb_tx < rx_pkts)) {
            printf("Drop packets %d\n", rx_pkts - nb_tx);
            do {
                rte_pktmbuf_free(pkts[nb_tx]);
            } while (++nb_tx < rx_pkts);
        }

#if 0
		if (rx_pkts == 0 && need_flush) {
			//for (i = 0; i < 2; i++) {
				sent = rte_eth_tx_buffer_flush(g_port_id,
							       g_queue_id,
							       tx_buffer[i]);
				g_tx_stats->tx[g_port_id] += sent;
			//}
			need_flush = 0;
			continue;
		}

		for (i = 0; i < rx_pkts; i++)
			handle_tx_packet(pkts[i]);

		need_flush = 1;
#endif        
	}
}

static void main_loop()
{
    if (g_func == FUNC_RX) {
        do_rx();
    } else if (g_func == FUNC_TX) {
        do_tx();
    }
}

/*
 * Application main function - loops through
 * receiving and processing packets. Never returns
 */
int
main(int argc, char *argv[])
{
	const struct rte_memzone *mz;
    unsigned lcore_id;
	struct rte_mempool *mp;
	int retval;


	if ((retval = rte_eal_init(argc, argv)) < 0)
		return -1;
	argc -= retval;
	argv += retval;

	if (parse_app_args(argc, argv) < 0)
		rte_exit(EXIT_FAILURE, "Invalid command-line arguments\n");

	if (rte_eth_dev_count_avail() == 0)
		rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");

	mp = rte_mempool_lookup(get_mbuf_pool_name(rte_socket_id()));
	if (mp == NULL)
		rte_exit(EXIT_FAILURE, "Cannot get mempool for mbufs\n");

	cl_rx_buf = calloc(64, sizeof(cl_rx_buf[0]));
    
    configure_output_ports();

	RTE_LOG(INFO, APP, "Finished Process Init.\n");

	printf("\nClient process %d handling packets\n", 0);
	printf("[Press Ctrl-C to quit ...]\n");

    main_loop();

	/* launch per-lcore init on every lcore */
	//rte_eal_mp_remote_launch(main_loop, NULL, CALL_MASTER);
	//RTE_LCORE_FOREACH_SLAVE(lcore_id) {
    //  if (rte_eal_wait_lcore(lcore_id) < 0) {
	//		retval = -1;
	//		break;
	//	}
	//}

    return 0;
}
