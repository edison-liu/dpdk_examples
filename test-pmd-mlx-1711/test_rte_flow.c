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

static void add_gre_flows(void)
{
    
}

static void add_gre_flows_offload(void)
{
    
}

void add_rte_flows(void)
{
    add_vlan_flow();
    add_ip_flow();
    add_icmp_flow();
    add_udp_flow();
    add_tcp_flow();
    //add_gre_flows();
    add_gre_flows_offload();
}