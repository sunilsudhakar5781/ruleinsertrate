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

#ifndef FLOW_COMMON_H_
#define FLOW_COMMON_H_

#include <rte_byteorder.h>

#include <doca_dev.h>
#include <doca_flow.h>

#define BE_IPV4_ADDR(a, b, c, d)                                               \
	(RTE_BE32(((uint32_t)a << 24) + (b << 16) + (c << 8) +                 \
		d)) /* create IPV4 address */
#define SET_IPV6_ADDR(addr, a, b, c, d)                                        \
    do {                                                                       \
        addr[0] = a & 0xffffffff;                                              \
        addr[1] = b & 0xffffffff;                                              \
        addr[2] = c & 0xffffffff;                                              \
        addr[3] = d & 0xffffffff;                                              \
    } while (0) /* create IPv6 address */
#define SET_MAC_ADDR(addr, a, b, c, d, e, f)                                   \
    do {                                                                       \
        addr[0] = a & 0xff;                                                    \
        addr[1] = b & 0xff;                                                    \
        addr[2] = c & 0xff;                                                    \
        addr[3] = d & 0xff;                                                    \
        addr[4] = e & 0xff;                                                    \
        addr[5] = f & 0xff;                                                    \
    } while (0) /* create source mac address */
#define BUILD_VNI(uint24_vni)                                                  \
    (RTE_BE32((uint32_t)uint24_vni << 8)) /* create VNI */
#define DEFAULT_TIMEOUT_US                                                     \
    (10000)                /* default timeout for processing entries           \
                            */
#define NB_ACTIONS_ARR (1) /* default length for action array */
#define SHARED_RESOURCE_NUM_VALUES                                             \
    (8) /* Number of doca_flow_shared_resource_type values */

#ifndef MAX
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#endif
#define MIN_ACTIONS_MEM_SIZE_PER_QUEUE (64) /* Minimal actions memory size required per queue */
#define ACTIONS_MEM_SIZE(nr_queues, entries) \
        rte_align32pow2(MAX((uint32_t)(entries * DOCA_FLOW_MAX_ENTRY_ACTIONS_MEM_SIZE), \
                            (uint32_t)(nr_queues * MIN_ACTIONS_MEM_SIZE_PER_QUEUE))) /* Total actions memory size */
#define ARRAY_DIM(a) (sizeof(a) / sizeof((a)[0]))
#define ARRAY_INIT(array, val) \
        do { \
                for (size_t i = 0; i < ARRAY_DIM(array); i++) { \
                        array[i] = val; \
                } \
        } while (0)

// Macro to initialize the CPU set to empty
#define CPU_ZERO(cpuset) memset((cpuset), 0, sizeof(cpu_set_t))
#define CPU_SET(cpu, cpuset) \
    ((cpuset)->__bits[(cpu) / (sizeof(unsigned long) * 8)] |= (1UL << ((cpu) % (sizeof(unsigned long) * 8))))

#define MAX_PORT_STR_LEN 128

struct entries_status
{
	bool failure; /* each entry status */
	uint32_t nb_processed; /* entries already processed */
};

struct flow_resources
{
	uint32_t nr_counters; /* number of counters to configure */
	uint32_t nr_meters;   /* number of traffic meters to configure */
};

/*
 * Initialize DOCA Flow library
 *
 * @nb_queues [in]: number of queues the sample will use
 * @mode [in]: doca flow architecture mode
 * @resource [in]: number of meters and counters to configure
 * @nr_shared_resources [in]: total shared resource per type
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise.
 */
doca_error_t
init_doca_flow(int nb_queues, const char* mode, struct flow_resources* resource,
	       uint32_t nr_shared_resources[]);

/*
 * Initialize DOCA Flow library with callback
 *
 * @nb_queues [in]: number of queues the sample will use
 * @mode [in]: doca flow architecture mode
 * @resource [in]: number of meters and counters to configure
 * @nr_shared_resources [in]: total shared resource per type
 * @cb [in]: entry process callback pointer
 * @pipe_process_cb [in]: pipe process callback pointer
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise.
 */
doca_error_t
init_doca_flow_cb(int nb_queues, const char* mode,
		  struct flow_resources* resource,
		  uint32_t nr_shared_resources[],
		  doca_flow_entry_process_cb cb,
		  doca_flow_pipe_process_cb pipe_process_cb,
		  int nb_queue_depth);

/*
 * Initialize DOCA Flow ports
 *
 * @nb_ports [in]: number of ports to create
 * @ports [in]: array of ports to create
 * @is_hairpin [in]: port pair should run if is_hairpin = true
 * @dev_arr [in]: doca device array for each port
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise.
 */
doca_error_t init_doca_flow_ports(int nb_ports, struct doca_flow_port *ports[],
				  bool is_hairpin, struct doca_dev *dev_arr[],
				  uint32_t actions_mem_size[]);
/*
 * Stop DOCA Flow ports
 *
 * @nb_ports [in]: number of ports to stop
 * @ports [in]: array of ports to stop
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise.
 */
doca_error_t
stop_doca_flow_ports(int nb_ports, struct doca_flow_port* ports[]);

/*
 * Entry processing callback
 *
 * @entry [in]: DOCA Flow entry pointer
 * @pipe_queue [in]: queue identifier
 * @status [in]: DOCA Flow entry status
 * @op [in]: DOCA Flow entry operation
 * @user_ctx [out]: user context
 */
void
check_for_valid_entry(struct doca_flow_pipe_entry* entry, uint16_t pipe_queue,
		      enum doca_flow_entry_status status,
		      enum doca_flow_entry_op op, void* user_ctx);

/*
 * Set DOCA Flow pipe configurations
 *
 * @cfg [in]: DOCA Flow pipe configurations
 * @name [in]: Pipe name
 * @type [in]: Pipe type
 * @is_root [in]: Indicates if the pipe is a root pipe
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise.
 */
doca_error_t
set_flow_pipe_cfg(struct doca_flow_pipe_cfg* cfg, const char* name,
		  enum doca_flow_pipe_type type, bool is_root);

void
check_entry_status(struct doca_flow_pipe_entry* entry, uint16_t pipe_queue,
		   enum doca_flow_entry_status status,
		   enum doca_flow_entry_op op, void* user_ctx);

#endif /* FLOW_COMMON_H_ */
