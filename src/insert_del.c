/*
 * Copyright (c) 2022 NVIDIA CORPORATION AND AFFILIATES.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted
 * provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright notice, this list of
 *       conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright notice, this list of
 *       conditions and the following disclaimer in the documentation and/or other materials
 *       provided with the distribution.
 *     * Neither the name of the NVIDIA CORPORATION nor the names of its contributors may be used
 *       to endorse or promote products derived from this software without specific prior written
 *       permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL NVIDIA CORPORATION BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TOR (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <string.h>
#include <unistd.h>

#include <rte_byteorder.h>

#include <doca_log.h>
#include <doca_flow.h>
#include <stdio.h>
#include <sched.h>
#include <pthread.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>

#include "flow_common.h"

DOCA_LOG_REGISTER(FLOW_MTHREAD_ADD_DEL);

/* Keep all queue depth values power of 2 */
#define HAIRPIN_PIPE_QDEPTH 1024
#define DROP_PIPE_QDEPTH 1024
#define CLASSIFIER_PIPE_QDEPTH 1024
#define ADD_THREADS 8 // Use only power of 2
#define MAX_IP_ADDRESSES DROP_PIPE_QDEPTH
#define MAX_IP_LENGTH 16       // Maximum length of an IPv4 address (xxx.xxx.xxx.xxx)

int g_lcore_count;

struct doca_flow_hairpin_pipe {
	struct doca_flow_pipe *pipe;
	struct doca_flow_pipe_entry *entry;
	struct doca_flow_port *port;
	struct entries_status status;
};

struct doca_flow_classifier_pipe {
	struct doca_flow_pipe *pipe;
	struct doca_flow_pipe_entry *entry;
	struct doca_flow_port *port;
	struct entries_status status;
};

struct doca_flow_drop_pipe {
	struct doca_flow_pipe *pipe;
	struct doca_flow_pipe_entry *entry[DROP_PIPE_QDEPTH];
	struct doca_flow_port *port;
	struct entries_status status;
	pthread_mutex_t mutex;
	int core_count;
	int rules_inserted;
	int rules_deleted;
};
	
pthread_t g_rule_del_thread[ADD_THREADS];
pthread_t g_rule_add_thread[ADD_THREADS];
doca_be32_t g_ipv4_addr[MAX_IP_ADDRESSES];

void generate_random_ip(doca_be32_t *ip)
{
	uint8_t octet1 = rand() % 256;
	uint8_t octet2 = rand() % 256;
	uint8_t octet3 = rand() % 256;
	uint8_t octet4 = rand() % 256;
	*ip = BE_IPV4_ADDR(octet1, octet2, octet3, octet4);
}

/*
 * Create DOCA Flow pipe that forwards all the traffic to the other port
 *
 * @port [in]: port of the pipe
 * @port_id [in]: port ID of the pipe
 * @pipe [out]: created pipe pointer
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise.
 */

static doca_error_t create_hairpin_pipe(struct doca_flow_port *port,
					int port_id, struct doca_flow_pipe **pipe)
{
	struct doca_flow_actions actions, *actions_arr[NB_ACTIONS_ARR];
	struct doca_flow_pipe_cfg *pipe_cfg;
	struct doca_flow_monitor monitor;
	struct doca_flow_match match;
	struct doca_flow_fwd fwd;
	doca_error_t result;

	memset(&match, 0, sizeof(match));
	memset(&monitor, 0, sizeof(monitor));
	memset(&actions, 0, sizeof(actions));
	memset(&fwd, 0, sizeof(fwd));

	monitor.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;

	actions_arr[0] = &actions;

	result = doca_flow_pipe_cfg_create(&pipe_cfg, port);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create doca_flow_pipe_cfg: %s", doca_error_get_descr(result));
		return result;
	}

	result = set_flow_pipe_cfg(pipe_cfg, "HAIRPIN_PIPE", DOCA_FLOW_PIPE_BASIC, false);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg: %s", doca_error_get_descr(result));
		goto destroy_pipe_cfg;
	}

	result = doca_flow_pipe_cfg_set_match(pipe_cfg, &match, NULL);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg match: %s", doca_error_get_descr(result));
		goto destroy_pipe_cfg;
	}

	result = doca_flow_pipe_cfg_set_actions(pipe_cfg, actions_arr, NULL, NULL, NB_ACTIONS_ARR);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg actions: %s", doca_error_get_descr(result));
		goto destroy_pipe_cfg;
	}

	result = doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, HAIRPIN_PIPE_QDEPTH);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set pipe size: %s", doca_error_get_descr(result));
		goto destroy_pipe_cfg;
	}

	result = doca_flow_pipe_cfg_set_monitor(pipe_cfg, &monitor);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg monitor: %s", doca_error_get_descr(result));
		goto destroy_pipe_cfg;
	}

	/* forwarding traffic to other port */
	fwd.type = DOCA_FLOW_FWD_PORT;
	fwd.port_id = port_id ^ 1;

	result = doca_flow_pipe_create(pipe_cfg, &fwd, NULL, pipe);
destroy_pipe_cfg:
	doca_flow_pipe_cfg_destroy(pipe_cfg);
return result;
}
/*
 * Create DOCA Flow pipe with match on header types to fwd to drop pipe with it's own match logic.
 * On miss, drop the packet.
 *
 * @port [in]: port of the pipe
 * @drop_pipe [in]: pipe to forward the traffic that didn't hit the pipe rules
 * @pipe [out]: created pipe pointer
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise.
 */
static doca_error_t create_classifier_pipe(struct doca_flow_port *port,
					   struct doca_flow_pipe *drop_pipe,
					   struct doca_flow_pipe **pipe)
{
	struct doca_flow_actions actions, *actions_arr[NB_ACTIONS_ARR];
	struct doca_flow_pipe_cfg *pipe_cfg;
	struct doca_flow_monitor monitor;
	struct doca_flow_fwd fwd_miss;
	struct doca_flow_match match;
	struct doca_flow_fwd fwd;
	doca_error_t result;

	memset(&match, 0, sizeof(match));
	memset(&actions, 0, sizeof(actions));
	memset(&monitor, 0, sizeof(monitor));
	memset(&fwd, 0, sizeof(fwd));
	memset(&fwd_miss, 0, sizeof(fwd_miss));

	/* Match on header types */
	match.parser_meta.outer_l3_type = DOCA_FLOW_L3_META_IPV4;
	match.parser_meta.outer_l4_type = DOCA_FLOW_L4_META_TCP;

	monitor.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;

	actions_arr[0] = &actions;

	result = doca_flow_pipe_cfg_create(&pipe_cfg, port);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create doca_flow_pipe_cfg: %s", doca_error_get_descr(result));
		return result;
	}

	result = set_flow_pipe_cfg(pipe_cfg, "CLASSIFIER_PIPE", DOCA_FLOW_PIPE_BASIC, true);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg: %s", doca_error_get_descr(result));
		goto destroy_pipe_cfg;
	}

	result = doca_flow_pipe_cfg_set_match(pipe_cfg, &match, NULL);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg match: %s", doca_error_get_descr(result));
		goto destroy_pipe_cfg;
	}

	result = doca_flow_pipe_cfg_set_actions(pipe_cfg, actions_arr, NULL, NULL, NB_ACTIONS_ARR);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg actions: %s", doca_error_get_descr(result));
		goto destroy_pipe_cfg;
	}

	result = doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, CLASSIFIER_PIPE_QDEPTH);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg nr_entries: %s", doca_error_get_descr(result));
		goto destroy_pipe_cfg;
	}

	result = doca_flow_pipe_cfg_set_monitor(pipe_cfg, &monitor);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg monitor: %s", doca_error_get_descr(result));
		goto destroy_pipe_cfg;
	}

	fwd.type = DOCA_FLOW_FWD_PIPE;
	fwd.next_pipe = drop_pipe;

	fwd_miss.type = DOCA_FLOW_FWD_DROP;

	result = doca_flow_pipe_create(pipe_cfg, &fwd, &fwd_miss, pipe);
destroy_pipe_cfg:
	doca_flow_pipe_cfg_destroy(pipe_cfg);
	return result;
}

/*
 * Add DOCA Flow pipe entry to the classifier or hairpin pipe
 *
 * @pipe [in]: pipe of the entry
 * @status [in]: user context for adding entry
 * @entry [out]: created entry pointer
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise.
 */
static doca_error_t add_pipe_entry(struct doca_flow_pipe *pipe,
				   struct entries_status *status,
				   struct doca_flow_pipe_entry **entry)
{
	struct doca_flow_match match;

	/* All fields are not changeable, thus we need to add only 1 entry,
	 * all values will be inherited from the pipe creation
	 */
	memset(&match, 0, sizeof(match));

	return doca_flow_pipe_add_entry(0, pipe, &match, NULL, NULL, NULL, 0, status, entry);
}

/*
 * Create DOCA Flow pipe with match and fwd drop action. miss fwd to hairpin pipe
 *
 * @port [in]: port of the pipe
 * @hairpin_pipe [in]: pipe to forward the traffic that didn't hit the pipe rules
 * @pipe [out]: created pipe pointer
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise.
 */
static doca_error_t create_drop_pipe(struct doca_flow_port *port,
				     struct doca_flow_pipe *hairpin_pipe,
				     struct doca_flow_pipe **pipe)
{
	struct doca_flow_actions actions, *actions_arr[NB_ACTIONS_ARR];
	struct doca_flow_pipe_cfg *pipe_cfg;
	struct doca_flow_monitor monitor;
	struct doca_flow_fwd fwd_miss;
	struct doca_flow_match match;
	struct doca_flow_fwd fwd;
	doca_error_t result;

	memset(&match, 0, sizeof(match));
	memset(&actions, 0, sizeof(actions));
	memset(&monitor, 0, sizeof(monitor));
	memset(&fwd, 0, sizeof(fwd));
	memset(&fwd_miss, 0, sizeof(fwd_miss));

	/* DOCA_FLOW_L3_TYPE_IP4 is a selector of underlying struct, pipe won't
	 * match on L3 header type being IP4. This part is done on previous
	 * pipe, a classifier.
	 */
	match.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
	match.outer.ip4.src_ip = 0xffffffff;
	match.outer.ip4.dst_ip = 0xffffffff;

	/* DOCA_FLOW_L4_TYPE_EXT_TCP is a selector of underlying struct,
	 * pipe won't match on L4 header type being TCP. This part is done
	 * on previous pipe, a classifier
	 */
	match.outer.l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_TCP;
	match.outer.tcp.l4_port.src_port = 0xffff;
	match.outer.tcp.l4_port.dst_port = 0xffff;

	monitor.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;

	actions_arr[0] = &actions;

	result = doca_flow_pipe_cfg_create(&pipe_cfg, port);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create doca_flow_pipe_cfg: %s", doca_error_get_descr(result));
		return result;
	}

	result = set_flow_pipe_cfg(pipe_cfg, "DROP_PIPE", DOCA_FLOW_PIPE_BASIC, false);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg: %s", doca_error_get_descr(result));
		goto destroy_pipe_cfg;
	}

	result = doca_flow_pipe_cfg_set_match(pipe_cfg, &match, NULL);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg match: %s", doca_error_get_descr(result));
		goto destroy_pipe_cfg;
	}

	result = doca_flow_pipe_cfg_set_actions(pipe_cfg, actions_arr, NULL, NULL, NB_ACTIONS_ARR);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg actions: %s", doca_error_get_descr(result));
		goto destroy_pipe_cfg;
	}

	result = doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, DROP_PIPE_QDEPTH);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg nr_entries: %s", doca_error_get_descr(result));
		goto destroy_pipe_cfg;
	}

	result = doca_flow_pipe_cfg_set_monitor(pipe_cfg, &monitor);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg monitor: %s", doca_error_get_descr(result));
		goto destroy_pipe_cfg;
	}

	fwd.type = DOCA_FLOW_FWD_DROP;

	fwd_miss.type = DOCA_FLOW_FWD_PIPE;
	fwd_miss.next_pipe = hairpin_pipe;

	result = doca_flow_pipe_create(pipe_cfg, &fwd, &fwd_miss, pipe);
destroy_pipe_cfg:
	doca_flow_pipe_cfg_destroy(pipe_cfg);
	return result;
}

static doca_error_t
classifier_pipe_create(struct doca_flow_classifier_pipe *pipe,
		       struct doca_flow_pipe *drop_pipe,
		       struct doca_flow_port *port,
		       int port_id)
{
	doca_error_t result;

	memset(&pipe->status, 0 , sizeof(pipe->status));
	result = create_classifier_pipe(port, drop_pipe, &pipe->pipe);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create classifier pipe %s", doca_error_get_descr(result));
		return result;
	}

	result = add_pipe_entry(pipe->pipe, &pipe->status, &pipe->entry);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to add entry to classifier pipe %s", doca_error_get_descr(result));
		return result;
	}

	result = doca_flow_entries_process(port, 0, DEFAULT_TIMEOUT_US, 1);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to process entries: %s", doca_error_get_descr(result));
		return result;
	}

	if (pipe->status.nb_processed != 1 || pipe->status.failure) {
		DOCA_LOG_ERR("Failed to process entrie");
		return 1;
	}

	pipe->port = port;
	return result;
}

static void classifier_pipe_destroy(struct doca_flow_pipe *pipe)
{
	doca_flow_pipe_destroy(pipe);
}

static doca_error_t drop_pipe_create(struct doca_flow_drop_pipe *pipe,
				     struct doca_flow_pipe *hairpin_pipe,
				     struct doca_flow_port *port)
{
	doca_error_t result;

	result = create_drop_pipe(port, hairpin_pipe, &pipe->pipe);
	if (result != DOCA_SUCCESS)
		DOCA_LOG_ERR("Failed to create classifier pipe %s", doca_error_get_descr(result));

	pipe->port = port;
	return result;
}

static void drop_pipe_destroy(struct doca_flow_pipe *pipe)
{
	doca_flow_pipe_destroy(pipe);
}

static doca_error_t hairpin_pipe_create(struct doca_flow_hairpin_pipe *pipe,
					struct doca_flow_port *port,
					int port_id)
{
	doca_error_t result;

	memset(&pipe->status, 0 , sizeof(pipe->status));
	result = create_hairpin_pipe(port, port_id, &pipe->pipe);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create classifier pipe %s", doca_error_get_descr(result));
		return result;
	}

	result = add_pipe_entry(pipe->pipe, &pipe->status, &pipe->entry);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to add entry to classifier pipe %s", doca_error_get_descr(result));
		return result;
	}

	result = doca_flow_entries_process(port, 0, DEFAULT_TIMEOUT_US, 1);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to process entries: %s", doca_error_get_descr(result));
		return result;
	}

	if (pipe->status.nb_processed != 1 || pipe->status.failure) {
		DOCA_LOG_ERR("Failed to process entrie");
		return 1;
	}

	pipe->port = port;
	return result;
}

static void hairpin_pipe_destroy(struct doca_flow_pipe *pipe)
{
	doca_flow_pipe_destroy(pipe);
}

static doca_error_t add_drop_pipe_entry(struct doca_flow_port *port,
					struct doca_flow_drop_pipe *pipe,
					int queue_id, doca_be32_t ipv4_addr)
{
	struct doca_flow_actions actions;
	struct doca_flow_match match;
	doca_error_t result;

	/* example 5-tuple to drop explicitly */
	doca_be32_t dst_ip_addr = ipv4_addr;
	doca_be32_t src_ip_addr = BE_IPV4_ADDR(1, 2, 3, 4);
	doca_be16_t dst_port = rte_cpu_to_be_16(80);
	doca_be16_t src_port = rte_cpu_to_be_16(1234);

	memset(&match, 0, sizeof(match));
	memset(&actions, 0, sizeof(actions));
	memset(&pipe->status, 0 , sizeof(pipe->status));

	match.outer.ip4.dst_ip = dst_ip_addr;
	match.outer.ip4.src_ip = src_ip_addr;
	match.outer.tcp.l4_port.dst_port = dst_port;
	match.outer.tcp.l4_port.src_port = src_port;

	result = doca_flow_pipe_add_entry(queue_id, pipe->pipe, &match, &actions,
					  NULL, NULL, DOCA_FLOW_NO_WAIT, &pipe->status,
					  &pipe->entry[pipe->rules_inserted]);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to add pipe entry: %s", doca_error_get_descr(result));
		return result;
	}

	result = doca_flow_entries_process(port, queue_id, DEFAULT_TIMEOUT_US, 1);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to process entries: %s", doca_error_get_descr(result));
		return result;
	}

	if (pipe->status.nb_processed != 1 || pipe->status.failure) {
		DOCA_LOG_ERR("Failed to process entry. nb_processed %d and status %d",
				pipe->status.nb_processed, pipe->status.failure);
		return 1;
	}

	return DOCA_SUCCESS;
}

static doca_error_t
add_drop_pipe_entry_no_process(struct doca_flow_port *port,
			       struct doca_flow_drop_pipe *pipe,
			       int queue_id, doca_be32_t ipv4_addr,
			       int flags)
{
	struct doca_flow_actions actions;
	struct doca_flow_match match;
	doca_error_t result;

	/* example 5-tuple to drop explicitly */
	doca_be32_t dst_ip_addr = ipv4_addr;
	doca_be32_t src_ip_addr = BE_IPV4_ADDR(1, 2, 3, 4);
	doca_be16_t dst_port = rte_cpu_to_be_16(80);
	doca_be16_t src_port = rte_cpu_to_be_16(1234);

	memset(&match, 0, sizeof(match));
	memset(&actions, 0, sizeof(actions));
	memset(&pipe->status, 0 , sizeof(pipe->status));

	match.outer.ip4.dst_ip = dst_ip_addr;
	match.outer.ip4.src_ip = src_ip_addr;
	match.outer.tcp.l4_port.dst_port = dst_port;
	match.outer.tcp.l4_port.src_port = src_port;

	result = doca_flow_pipe_add_entry(queue_id, pipe->pipe, &match, &actions,
					  NULL, NULL, flags, &pipe->status,
					  &pipe->entry[pipe->rules_inserted]);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to add pipe entry: %s", doca_error_get_descr(result));
		return result;
	}
	return DOCA_SUCCESS;
}

static doca_error_t
remove_drop_pipe_entry_no_process(int queue_id, struct doca_flow_drop_pipe *pipe,
				  int flags)
{
	doca_error_t result;

	result = doca_flow_pipe_remove_entry(queue_id, flags,
					     pipe->entry[pipe->rules_deleted]);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to remove pipe entry: %s", doca_error_get_descr(result));
		return result;
	}
	return result;
}

static doca_error_t
remove_drop_pipe_entry(int queue_id, struct doca_flow_drop_pipe *pipe)
{
	doca_error_t result;

	result = doca_flow_pipe_remove_entry(queue_id, DOCA_FLOW_NO_WAIT,
					     pipe->entry[pipe->rules_deleted]);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to remove pipe entry: %s", doca_error_get_descr(result));
		return result;
	}

	result = doca_flow_entries_process(pipe->port, queue_id, DEFAULT_TIMEOUT_US, 1);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to process entries: %s", doca_error_get_descr(result));
		return result;
	}
	return result;
}

void *drop_rule_add(void *arg)
{
	struct doca_flow_drop_pipe *pipe = (struct doca_flow_drop_pipe *)arg;
	int entries_to_post_per_thread;
	doca_error_t result;
	int arr_start_idx;
	cpu_set_t cpuset;
	int cpu;

	/* Set Affinity of this thread */
	pthread_mutex_lock(&pipe->mutex);
	cpu = pipe->core_count % g_lcore_count;
	entries_to_post_per_thread = MAX_IP_ADDRESSES / ADD_THREADS;
	arr_start_idx =  entries_to_post_per_thread * cpu;
	CPU_ZERO(&cpuset);
	CPU_SET(cpu, &cpuset);
	pipe->core_count++;
	pthread_mutex_unlock(&pipe->mutex);

	pthread_t thread = pthread_self();
	int ret = pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset);
	if (ret != 0) {
		DOCA_LOG_ERR("Error setting thread affinity %d with err: %d", pipe->core_count, ret);
		return NULL;
	}

	while (1) {

		pthread_mutex_lock(&pipe->mutex);
		/* Post DROP_PIPE_QDEPTH and wait for deletions */
		if (pipe->rules_inserted == DROP_PIPE_QDEPTH - 1) {
			pthread_mutex_unlock(&pipe->mutex);
			break;
		}

		/* Insert drop rule */
		result = add_drop_pipe_entry(pipe->port, pipe, 0, g_ipv4_addr[arr_start_idx]);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to add drop entry %s", doca_error_get_descr(result));
			pthread_mutex_unlock(&pipe->mutex);
			break;
		}

		pipe->rules_inserted++;
		arr_start_idx++;
		pthread_mutex_unlock(&pipe->mutex);
		if (arr_start_idx == entries_to_post_per_thread - 1)
			break;
		pthread_testcancel();
	}
	return NULL;
}

void *drop_rule_del(void *arg)
{
	struct doca_flow_drop_pipe *pipe = (struct doca_flow_drop_pipe *)arg;
	doca_error_t result;
	cpu_set_t cpuset;
	int cpu;

	/* Set Affinity of this thread */
	pthread_mutex_lock(&pipe->mutex);
	cpu = pipe->core_count % g_lcore_count;
	CPU_ZERO(&cpuset);
	CPU_SET(cpu, &cpuset);
	pipe->core_count++;
	pthread_mutex_unlock(&pipe->mutex);

	pthread_t thread = pthread_self();
	int ret = pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset);
	if (ret != 0) {
		fprintf(stderr, "Error setting thread affinity: %d\n", ret);
		return NULL;
	}

	while (1) {
		
		pthread_mutex_lock(&pipe->mutex);
		/* Post DROP_PIPE_QDEPTH and wait for deletions */
		if (pipe->rules_deleted == DROP_PIPE_QDEPTH - 1) {
			pthread_mutex_unlock(&pipe->mutex);
			break;
		}
		
		/* delete drop rule */
		result = remove_drop_pipe_entry (0, pipe);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to add drop entry %s", doca_error_get_descr(result));
			pthread_mutex_unlock(&pipe->mutex);
			break;
		}

		pipe->rules_deleted++;
		pthread_mutex_unlock(&pipe->mutex);
	}
	return NULL;
}

void pipe_init(struct doca_flow_drop_pipe *pipe)
{
	pipe->core_count = 0;
	pipe->rules_inserted = 0;
	pipe->rules_deleted = 0;
}

void rule_add_wait(struct doca_flow_drop_pipe *pipe)
{
	int spin = true;

	do {
		pthread_mutex_lock(&pipe->mutex);
		if (pipe->rules_inserted == DROP_PIPE_QDEPTH - 1)
			spin = false;
		pthread_mutex_unlock(&pipe->mutex);
	} while (spin);
}

void rule_del_wait(struct doca_flow_drop_pipe *pipe)
{
	int spin = true;
	do {
		pthread_mutex_lock(&pipe->mutex);
		if (pipe->rules_deleted == DROP_PIPE_QDEPTH - 1)
			spin = false;
		pthread_mutex_unlock(&pipe->mutex);
	} while (spin);
}

int rule_add_thread_spawn(struct doca_flow_drop_pipe *pipe)
{
	int i, ret;

	for (i = 0; i < ADD_THREADS; i++) {
		ret = pthread_create(&g_rule_add_thread[i], NULL,
				     drop_rule_add, (void *)pipe);
		if (ret != 0) {
			DOCA_LOG_ERR("Error creating g_rule_add_thread: %d\n", ret);
			return ret;
		}
	}
	return 0;
}

int rule_del_thread_spawn(struct doca_flow_drop_pipe *pipe)
{
	int i, ret;

	for (i = 0; i < ADD_THREADS; i++) {
		ret = pthread_create(&g_rule_del_thread[i], NULL,
				     drop_rule_del, (void *)pipe);
		if (ret != 0) {
			DOCA_LOG_ERR("Error creating g_rule_add_thread: %d\n", ret);
			return ret;
		}
	}
	return 0;
}

int all_threads_cancel(void)
{
	int ret, i;

	for (i = 0; i < ADD_THREADS; i++) {
		ret = pthread_cancel(g_rule_add_thread[i]);
		if (ret != 0) {
			DOCA_LOG_ERR("Error cancelling rule_add thread %d", ret);
			return ret;
		}
		ret = pthread_cancel(g_rule_del_thread[i]);
		if (ret != 0) {
			DOCA_LOG_ERR("Error cancelling rule_add thread %d", ret);
			return ret;
		}
	}
	return 0;
}

int all_threads_cancel_wait(void)
{
	int ret, i;

	for (i = 0; i < ADD_THREADS; i++) {
		ret = pthread_join(g_rule_add_thread[i], NULL);
		if (ret != 0) {
			DOCA_LOG_ERR("Error joining thread: %d\n", ret);
			return ret;
		}
		ret = pthread_join(g_rule_del_thread[i], NULL);
		if (ret != 0) {
			DOCA_LOG_ERR("Error joining thread: %d\n", ret);
			return ret;
		}
	}
	return 0;
}

doca_error_t single_core_post_process(struct doca_flow_drop_pipe *pipe)
{
	double execution_time;
	doca_error_t result;
	clock_t start;
	clock_t end;

	pipe_init(pipe);

	start = clock();
	result = add_drop_pipe_entry(pipe->port, pipe, 0, g_ipv4_addr[0]);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to add drop entry %s", doca_error_get_descr(result));
		return result;
	}

	end = clock();
	execution_time = (double)(end - start) / CLOCKS_PER_SEC;
	pipe->rules_inserted++;
	DOCA_LOG_ERR("Single pipe entry and process took %f seconds", execution_time);
	return result;
}

doca_error_t single_core_remove_process(struct doca_flow_drop_pipe *pipe)
{
	double execution_time;
	doca_error_t result;
	clock_t start;
	clock_t end;

	start = clock();
	result = remove_drop_pipe_entry(0, pipe);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to remove drop entry %s", doca_error_get_descr(result));
		return result;
	}

	end = clock();
	execution_time = (double)(end - start) / CLOCKS_PER_SEC;
	pipe->rules_deleted++;
	DOCA_LOG_ERR("Single pipe remove and process took %f seconds", execution_time);
	return result;
}

doca_error_t single_core_multi_rule_single_post_process(struct doca_flow_drop_pipe *pipe)
{
	double execution_time;
	doca_error_t result;
	clock_t start;
	clock_t end;

	pipe_init(pipe);
	start = clock();

	while (1) {
		/* Post DROP_PIPE_QDEPTH and wait for deletions */
		if (pipe->rules_inserted == DROP_PIPE_QDEPTH - 1) {
			break;
		}

		/* Insert drop rule */
		result = add_drop_pipe_entry(pipe->port, pipe, 0, g_ipv4_addr[pipe->rules_inserted]);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to add drop entry %s", doca_error_get_descr(result));
			break;
		}

		pipe->rules_inserted++;
	}

	end = clock();
	execution_time = (double)(end - start) / CLOCKS_PER_SEC;
	DOCA_LOG_ERR("Added %d rules from core %d in %f seconds", pipe->rules_inserted + 1, sched_getcpu(),
								  execution_time);
	return result;
}

doca_error_t single_core_multi_rule_single_remove_process(struct doca_flow_drop_pipe *pipe)
{
	double execution_time;
	doca_error_t result;
	clock_t start;
	clock_t end;

	pipe_init(pipe);
	start = clock();

	while (1) {
		/* Post DROP_PIPE_QDEPTH and wait for deletions */
		if (pipe->rules_deleted == DROP_PIPE_QDEPTH - 1) {
			break;
		}

		/* Insert drop rule */
		result = remove_drop_pipe_entry(0, pipe);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to remove drop entry %s", doca_error_get_descr(result));
			break;
		}

		pipe->rules_deleted++;
	}

	end = clock();
	execution_time = (double)(end - start) / CLOCKS_PER_SEC;
	DOCA_LOG_ERR("Removed %d rules from core %d in %f seconds", pipe->rules_deleted + 1, sched_getcpu(),
								    execution_time);
	return result;
}

int multi_core_multi_rule_single_post_process(struct doca_flow_drop_pipe *pipe)
{
        double execution_time;
        clock_t start;
        clock_t end;
	int ret;

	/* Init mutex */
	pthread_mutex_init(&pipe->mutex, NULL);	

	pipe_init(pipe);

	/* Spawn thread to add rules */
	start = clock();
	ret = rule_add_thread_spawn(pipe);
	if (ret) {
		DOCA_LOG_ERR("rule_add_thread_spawn failed with err %d", ret);
		return ret;
	}

	/* Wait for rules to be added */
	rule_add_wait(pipe);
	end = clock();
	execution_time = (double)(end - start) / CLOCKS_PER_SEC;
	DOCA_LOG_ERR("Multi core insertion (%d threads) for %d entries took %f seconds", ADD_THREADS, pipe->rules_inserted + 1, execution_time);
	pthread_mutex_destroy(&pipe->mutex);
	return ret;
}

int multi_core_multi_rule_single_remove_process(struct doca_flow_drop_pipe *pipe)
{
	double execution_time;
	clock_t start;
	clock_t end;
	int ret;

	/* Init mutex */
	pthread_mutex_init(&pipe->mutex, NULL);

	/* Spawn thread to add rules */
	start = clock();
	ret = rule_del_thread_spawn(pipe);
	if (ret) {
		DOCA_LOG_ERR("rule_del_thread_spawn failed with err %d", ret);
		return ret;
	}

	/* Wait for rules to be added */
	rule_del_wait(pipe);
	end = clock();
	execution_time = (double)(end - start) / CLOCKS_PER_SEC;
	DOCA_LOG_ERR("Multi core deletion (%d threads) for %d entries took %f seconds", ADD_THREADS, pipe->rules_deleted + 1, execution_time);
	pthread_mutex_destroy(&pipe->mutex);
	return ret;
}

doca_error_t single_core_multi_rule_batch_add_process(struct doca_flow_drop_pipe *pipe)
{
	enum doca_flow_flags_type flags = DOCA_FLOW_WAIT_FOR_BATCH;
	int num_entries = DROP_PIPE_QDEPTH;
	double process_execution_time;
	doca_error_t result;
	clock_t start;
	clock_t end;
	int i;

	pipe_init(pipe);
	start = clock();
	for (i = 0; i < num_entries; i++) {
		if (i == num_entries - 1)
			flags = DOCA_FLOW_NO_WAIT;

                result = add_drop_pipe_entry_no_process(pipe->port, pipe, 0, g_ipv4_addr[pipe->rules_inserted], flags);
                if (result != DOCA_SUCCESS) {
                        DOCA_LOG_ERR("Failed to add drop entry %s", doca_error_get_descr(result));
                        break;
                }
		pipe->rules_inserted++;

	}

	do {
                result = doca_flow_entries_process(pipe->port,
                                                   0,
                                                   DEFAULT_TIMEOUT_US,
                                                   num_entries - pipe->status.nb_processed);
                if (result != DOCA_SUCCESS) {
                        DOCA_LOG_ERR("Failed to process entries: %s", doca_error_get_descr(result));
                        return result;
                }
                if (pipe->status.failure) {
                        DOCA_LOG_ERR("Failed to process entries, status is not success");
                        return DOCA_ERROR_BAD_STATE;
                }
        } while (pipe->status.nb_processed < num_entries);
	end = clock();
	process_execution_time = (double)(end - start) / CLOCKS_PER_SEC;
	DOCA_LOG_ERR("Batch Add/process %d entries from core %d in %f seconds", pipe->rules_inserted, sched_getcpu(), process_execution_time);

	return result;
}

doca_error_t single_core_multi_rule_batch_remove_process(struct doca_flow_drop_pipe *pipe)
{
        doca_error_t result;
        int num_entries = DROP_PIPE_QDEPTH;
        double execution_time;
        clock_t start;
        clock_t end;
        int i;
        enum doca_flow_flags_type flags = DOCA_FLOW_WAIT_FOR_BATCH;

        pipe_init(pipe);
        start = clock();
        for (i = 0; i < num_entries; i++) {
                if (i == num_entries - 1)
                        flags = DOCA_FLOW_NO_WAIT;

		memset(&pipe->status, 0 , sizeof(pipe->status));
                result = remove_drop_pipe_entry_no_process(0, pipe, flags);
                if (result != DOCA_SUCCESS) {
                        DOCA_LOG_ERR("Failed to add drop entry %s", doca_error_get_descr(result));
                        break;
                }
		pipe->rules_deleted++;

        }

        do {
		memset(&pipe->status, 0 , sizeof(pipe->status));
                result = doca_flow_entries_process(pipe->port,
                                                   0,
                                                   DEFAULT_TIMEOUT_US,
                                                   num_entries - pipe->status.nb_processed);
                if (result != DOCA_SUCCESS) {
                        DOCA_LOG_ERR("Failed to process entries: %s", doca_error_get_descr(result));
                        return result;
                }
		/* TODO Check why status.failure is 1 only for batch delete */

        } while (pipe->status.nb_processed < num_entries);
        end = clock();
        execution_time = (double)(end - start) / CLOCKS_PER_SEC;
        DOCA_LOG_ERR("Batch remove/process of %d entries from core %d in %f seconds", pipe->rules_deleted, sched_getcpu(), execution_time);
        return result;
}

/*
 * Run flow_mthread_add_del sample
 *
 * @nb_queues [in]: number of queues the sample will use
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise.
 */
doca_error_t flow_mthread_add_del(int nb_queues)
{
	const int nb_ports = 2;
	const int nb_entries = 2 * DROP_PIPE_QDEPTH;
	struct flow_resources resource = {0};
	uint32_t nr_shared_resources[SHARED_RESOURCE_NUM_VALUES] = {0};
	struct doca_flow_port *ports[nb_ports];
	uint32_t actions_mem_size[nb_ports];
	struct doca_dev *dev_arr[nb_ports];
	doca_error_t result;
	int port_id;
	struct doca_flow_classifier_pipe classifier_pipe[2];
	struct doca_flow_hairpin_pipe hairpin_pipe[2];
	struct doca_flow_drop_pipe drop_pipe[2];
	int ret;

	resource.nr_counters = 80 + nb_ports * nb_entries;
	g_lcore_count = rte_lcore_count();
        result = init_doca_flow_cb(nb_queues,
                                   "vnf,hws",
                                   &resource,
                                   nr_shared_resources,
                                   check_entry_status,
                                   NULL, DROP_PIPE_QDEPTH);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to init DOCA Flow: %s", doca_error_get_descr(result));
		return result;
	}

        memset(dev_arr, 0, sizeof(struct doca_dev *) * nb_ports);
        ARRAY_INIT(actions_mem_size, ACTIONS_MEM_SIZE(nb_queues, nb_entries));
        result = init_doca_flow_ports(nb_ports, ports, true, dev_arr, actions_mem_size);	
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to init DOCA ports: %s", doca_error_get_descr(result));
		doca_flow_destroy();
		return result;
	}

	/* Create Pipes */
	for (port_id = 0; port_id < nb_ports; port_id++) {
		result = hairpin_pipe_create(&hairpin_pipe[port_id], ports[port_id], port_id);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to create hairpin pipe %s", doca_error_get_descr(result));
			goto end;
		}

		result = drop_pipe_create(&drop_pipe[port_id], hairpin_pipe[port_id].pipe, ports[port_id]);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to create drop pipe %s", doca_error_get_descr(result));
			goto end;
		}

		result = classifier_pipe_create(&classifier_pipe[port_id], drop_pipe[port_id].pipe, ports[port_id], port_id);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to create drop pipe %s", doca_error_get_descr(result));
			goto end;
		}
	}

	/* Generate and save all IP address in array */
	for (int i = 0; i < MAX_IP_ADDRESSES;  i++)
		generate_random_ip(&g_ipv4_addr[i]);

	/* single core, single rule add */
	result = single_core_post_process(&drop_pipe[0]);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("single_core_post_process failed with error %s", doca_error_get_descr(result));
		goto end;
	}

	/* single core, single rule remove */
	result = single_core_remove_process(&drop_pipe[0]);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("single_entry_remove failed with error %s", doca_error_get_descr(result));
		goto end;
	}

	/* Single core, multiple rules, No batch post and process */
	result = single_core_multi_rule_single_post_process(&drop_pipe[0]);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("single_core_multi_rule_single_post_process failed with error %s", doca_error_get_descr(result));
		goto end;
	}

	/* Single core,  multiple rules, No batch remove and process */
	result = single_core_multi_rule_single_remove_process(&drop_pipe[0]);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("single_core_multi_rule_single_remove_process failed with error %s", doca_error_get_descr(result));
		goto end;
	}

	/* multi core, multiple rules, single post and process */
	result = multi_core_multi_rule_single_post_process(&drop_pipe[0]);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("multi_core_multi_rule_single_post_process failed with error %s", doca_error_get_descr(result));
		goto end;
	}

	/* multi core, multiple rules, single remove and process */
	result = multi_core_multi_rule_single_remove_process(&drop_pipe[0]);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("multi_core_multi_rule_single_remove_process failed with error %s", doca_error_get_descr(result));
		goto end;
	}

	ret = all_threads_cancel();
	if (ret) {
		DOCA_LOG_ERR("all_threads_cancel failed with err %d", ret);
		goto end;
	}

	/* Wait for the thread to complete */
	ret = all_threads_cancel_wait();
	if (ret) {
		DOCA_LOG_ERR("all_threads_cancel_wait failed with err %d", ret);
		goto end;
	}

	/* Single core, multiple rules, batch add */
	result = single_core_multi_rule_batch_add_process(&drop_pipe[0]);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("single_core_multi_rule_batch_post_process failed with error %s", doca_error_get_descr(result));
		goto end;
	}

	/* Single core, multiple rules, batch remove */
	result = single_core_multi_rule_batch_remove_process(&drop_pipe[0]);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("single_core_multi_rule_batch_remove_process failed with error %s", doca_error_get_descr(result));
		goto end;
	}

end:
	for (port_id = 0; port_id < nb_ports; port_id++) {
		classifier_pipe_destroy(classifier_pipe[port_id].pipe);
		drop_pipe_destroy(drop_pipe[port_id].pipe);
		hairpin_pipe_destroy(hairpin_pipe[port_id].pipe);
	}
	result = stop_doca_flow_ports(nb_ports, ports);
	doca_flow_destroy();
	return result;
}
