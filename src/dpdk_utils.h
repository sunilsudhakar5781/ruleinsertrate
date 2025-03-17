/*
 * Copyright (c) 2024-2025 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of NVIDIA CORPORATION &
 * AFFILIATES (the "Company") and all right, title, and interest in and to the
 * software product, including all associated intellectual property rights, are
 * and shall remain exclusively with the Company.
 *
 * This software product is governed by the End User License Agreement
 * provided with the software product.
 *
 */

#ifndef COMMON_DPDK_UTILS_H_
#define COMMON_DPDK_UTILS_H_

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include <rte_flow.h>
#include <rte_mbuf.h>

#include <doca_error.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define RX_RING_SIZE 1024 /* RX ring size */
#define TX_RING_SIZE 1024 /* TX ring size */
#define NUM_MBUFS                                                             \
    (8 * 1024)              /* Number of mbufs to be allocated in the mempool */
#define MBUF_CACHE_SIZE 250 /* mempool cache size */
#define MAX_PORTS 16        /* Maximum number of ports */

/* Port configuration */
struct application_port_config
{
	int nb_ports;       /* Set on init to 0 for don't care, required ports
			       otherwise */
	uint16_t nb_queues; /* Set on init to 0 for don't care, required minimum
			       cores otherwise */
	int nb_hairpin_q;   /* Set on init to 0 to disable, hairpin queues
			       otherwise */
	uint16_t enable_mbuf_metadata : 1; /* Set on init to 0 to disable, otherwise
					      it will add meta to each mbuf */
	uint16_t self_hairpin : 1; /* Set on init to 1 enable both self and peer
				      hairpin */
	uint16_t rss_support : 1;  /* Set on init to 0 for no RSS support, RSS
				      support  otherwise */
	uint16_t lpbk_support : 1; /* Enable loopback support */
	uint16_t isolated_mode : 1; /* Set on init to 0 for no isolation,
				       isolated mode otherwise */
	uint16_t switch_mode : 1;   /* Set on init to 1 for switch mode */
};

/* DPDK configuration */
struct application_dpdk_config
{
	struct application_port_config
		port_config;          /* DPDK port configuration */
	bool reserve_main_thread; /* Reserve lcore for the main thread */
	struct rte_mempool* mbuf_pool;

	/* NxN matrix of hairpin queues. hairpin_queues[x][y] is the base queue
	 * number from port x to port y
	 */
	uint16_t hairpin_queues[MAX_PORTS][MAX_PORTS];
	/* hairpin_q_count is the number of hairpin queues between each pair of
	 * ports range will be from hairpin_queues[x][y] to hairpin_queues[x][y]
	 * + hairpin_q_count - 1
	 */
	uint8_t hairpin_q_count;
	/* worker cores which will not be used for a PMD and will not require a queue */
	uint8_t reserved_cores;
};

/*
* Initialize DPDK environment
*
* @argc [in]: number of program command line arguments
* @argv [in]: program command line arguments
* @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
*/
doca_error_t dpdk_init(int argc, char** argv);

/*
* Destroy DPDK environment
*/
void dpdk_fini(void);

/*
* Initialize DPDK ports and queues
*
* @app_dpdk_config [in/out]: application DPDK configuration values
* @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
*/
doca_error_t
dpdk_queues_and_ports_init(struct application_dpdk_config* app_dpdk_config);

/*
* Destroy DPDK ports and queues
*
* @app_dpdk_config [in]: application DPDK configuration values
*/
void
dpdk_queues_and_ports_fini(struct application_dpdk_config* app_dpdk_config);
#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* COMMON_DPDK_UTILS_H_ */
