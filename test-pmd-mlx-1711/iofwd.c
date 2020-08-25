/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
 *   All rights reserved.
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
 *     * Neither the name of Intel Corporation nor the names of its
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

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <inttypes.h>

#include <sys/queue.h>
#include <sys/stat.h>

#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_debug.h>
#include <rte_cycles.h>
#include <rte_memory.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_memcpy.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_string_fns.h>
#include <rte_flow.h>

#include "testpmd.h"

extern uint32_t vswitch_enable;


static void handle_burst(struct rte_mbuf **pkts_burst, uint16_t nb_rx)
{
	uint32_t i, tmp;
	struct ether_hdr *out_eth_hdr;
	struct ipv4_hdr *out_ipv4_hdr, *in_ipv4_hdr;
	struct gre_hdr *gre_hdr;

	for (i = 0; i < (uint32_t)nb_rx; i++) {
		if (likely(i < (uint32_t)nb_rx - 1))
			rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[i + 1],
							   void *));
		pkts_burst[i]->udata32 = RTE_BE32(0x12345678);
		pkts_burst[i]->ol_flags |= PKT_TX_METADATA;
	
		/* swap src and dst IP */
		out_eth_hdr = rte_pktmbuf_mtod(pkts_burst[i], struct ether_hdr *);
		out_ipv4_hdr = rte_pktmbuf_mtod_offset(pkts_burst[i], struct ipv4_hdr *,
						   sizeof(struct ether_hdr));
		gre_hdr = rte_pktmbuf_mtod_offset(pkts_burst[i], struct gre_hdr *,
						   sizeof(struct gre_hdr));
		in_ipv4_hdr = rte_pktmbuf_mtod_offset(pkts_burst[i], struct ipv4_hdr *,
						   sizeof(struct ether_hdr));
		tmp = in_ipv4_hdr->src_addr;
		in_ipv4_hdr->src_addr = in_ipv4_hdr->dst_addr;
		in_ipv4_hdr->dst_addr = tmp;
		printf("Inner IP %08x -> %08x\n", in_ipv4_hdr->src_addr, in_ipv4_hdr->dst_addr);
	}

}


/*
 * Forwarding of packets in I/O mode.
 * Forward packets "as-is".
 * This is the fastest possible forwarding operation, as it does not access
 * to packets data.
 */
static void
pkt_burst_io_forward(struct fwd_stream *fs)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	uint16_t nb_rx;
	uint16_t nb_tx;
	uint32_t retry;
	uint32_t i;

#ifdef RTE_TEST_PMD_RECORD_CORE_CYCLES
	uint64_t start_tsc;
	uint64_t end_tsc;
	uint64_t core_cycles;
#endif

#ifdef RTE_TEST_PMD_RECORD_CORE_CYCLES
	start_tsc = rte_rdtsc();
#endif

	/*
	 * Receive a burst of packets and forward them.
	 */
	nb_rx = rte_eth_rx_burst(fs->rx_port, fs->rx_queue,
			pkts_burst, nb_pkt_per_burst);
	if (unlikely(nb_rx == 0))
		return;
	fs->rx_packets += nb_rx;
	if (unlikely(verbose_level & 0x1))
		dump_pkt_burst(fs, pkts_burst, nb_rx, 1);

	handle_burst(pkts_burst, nb_rx);

	if (vswitch_enable) {
		for (i = 0; i < (uint32_t)nb_rx; i++) {
			if (likely(i < (uint32_t)nb_rx - 1))
				rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[i + 1],
							       void *));
			pkts_burst[i]->udata64 = vswitch_get_metadata(pkts_burst[i]);
			if (unlikely(verbose_level & 0x1))
				printf("iofwd: set meta %016lX\n", pkts_burst[i]->udata64);

		}
	}

#ifdef RTE_TEST_PMD_RECORD_BURST_STATS
	fs->rx_burst_stats.pkt_burst_spread[nb_rx]++;
#endif
	nb_tx = rte_eth_tx_burst(fs->tx_port, fs->tx_queue,
			pkts_burst, nb_rx);
	/*
	 * Retry if necessary
	 */
	if (unlikely(nb_tx < nb_rx) && fs->retry_enabled) {
		retry = 0;
		while (nb_tx < nb_rx && retry++ < burst_tx_retry_num) {
			rte_delay_us(burst_tx_delay_time);
			nb_tx += rte_eth_tx_burst(fs->tx_port, fs->tx_queue,
					&pkts_burst[nb_tx], nb_rx - nb_tx);
		}
	}
	fs->tx_packets += nb_tx;
#ifdef RTE_TEST_PMD_RECORD_BURST_STATS
	fs->tx_burst_stats.pkt_burst_spread[nb_tx]++;
#endif
	if (unlikely(nb_tx < nb_rx)) {
		fs->fwd_dropped += (nb_rx - nb_tx);
		do {
			rte_pktmbuf_free(pkts_burst[nb_tx]);
		} while (++nb_tx < nb_rx);
	}
#ifdef RTE_TEST_PMD_RECORD_CORE_CYCLES
	end_tsc = rte_rdtsc();
	core_cycles = (end_tsc - start_tsc);
	fs->core_cycles = (uint64_t) (fs->core_cycles + core_cycles);
#endif
}

struct fwd_engine io_fwd_engine = {
	.fwd_mode_name  = "io",
	.port_fwd_begin = NULL,
	.port_fwd_end   = NULL,
	.packet_fwd     = pkt_burst_io_forward,
};
