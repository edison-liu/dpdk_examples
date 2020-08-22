/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2017 Intel Corporation. All rights reserved.
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

#ifndef _CMDLINE_MTR_H_
#define _CMDLINE_MTR_H_

/* Traffic Metering and Policing */
extern cmdline_parse_inst_t cmd_add_port_meter_profile_srtcm;
extern cmdline_parse_inst_t cmd_add_port_meter_profile_trtcm;
extern cmdline_parse_inst_t cmd_add_port_meter_profile_trtcm_rfc4115;
extern cmdline_parse_inst_t cmd_del_port_meter_profile;
extern cmdline_parse_inst_t cmd_set_port_meter;
extern cmdline_parse_inst_t cmd_del_port_meter;
extern cmdline_parse_inst_t cmd_set_port_meter_profile;
extern cmdline_parse_inst_t cmd_enable_port_meter;
extern cmdline_parse_inst_t cmd_disable_port_meter;
extern cmdline_parse_inst_t cmd_set_port_meter_policer_action;
extern cmdline_parse_inst_t cmd_set_port_meter_stats_mask;
extern cmdline_parse_inst_t cmd_show_port_meter_stats;

#endif /* _CMDLINE_MTR_H_ */
