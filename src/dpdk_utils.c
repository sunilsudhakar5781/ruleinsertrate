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

#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_malloc.h>

#include <doca_buf_inventory.h>
#include <doca_log.h>
#include <doca_mmap.h>

#include "dpdk_utils.h"

DOCA_LOG_REGISTER(NUTILS);

#define RSS_KEY_LEN 40

/*
 * Bind port to all the peer ports
 *
 * @port_id [in]: port ID
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t bind_hairpin_queues(uint16_t port_id)
{
	/* Configure the Rx and Tx hairpin queues for the selected port */
	int result = 0, peer_port, peer_ports_len;
	uint16_t peer_ports[RTE_MAX_ETHPORTS];

	/* bind current Tx to all peer Rx */
	peer_ports_len = rte_eth_hairpin_get_peer_ports(port_id, peer_ports, RTE_MAX_ETHPORTS, 1);
	if (peer_ports_len < 0) {
		DOCA_LOG_ERR("Failed to get hairpin peer Rx ports of port %d, (%d)", port_id, peer_ports_len);
		return DOCA_ERROR_DRIVER;
	}

	for (peer_port = 0; peer_port < peer_ports_len; peer_port++) {
		result = rte_eth_hairpin_bind(port_id, peer_ports[peer_port]);
		if (result < 0) {
			DOCA_LOG_ERR("Failed to bind hairpin queues (%d)", result);
			return DOCA_ERROR_DRIVER;
		}
	}
	
	/* bind all peer Tx to current Rx */
	peer_ports_len = rte_eth_hairpin_get_peer_ports(port_id, peer_ports, RTE_MAX_ETHPORTS, 0);
	if (peer_ports_len < 0) {
		DOCA_LOG_ERR("Failed to get hairpin peer Tx ports of port %d, (%d)", port_id, peer_ports_len);
		return DOCA_ERROR_DRIVER;
	}

	for (peer_port = 0; peer_port < peer_ports_len; peer_port++) {
		result = rte_eth_hairpin_bind(peer_ports[peer_port], port_id);
		if (result < 0) {
			DOCA_LOG_ERR("Failed to bind hairpin queues (%d)", result);
			return DOCA_ERROR_DRIVER;
		}
	}
	return DOCA_SUCCESS;
}

/*
 * Unbind port from all its peer ports
 *
 * @port_id [in]: port ID
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
unbind_hairpin_queues(uint16_t port_id)
{
	/* Configure the Rx and Tx hairpin queues for the selected port */
	int result = 0, peer_port, peer_ports_len;
	uint16_t peer_ports[RTE_MAX_ETHPORTS];

	/* unbind current Tx from all peer Rx */
	peer_ports_len = rte_eth_hairpin_get_peer_ports(
			port_id, peer_ports, RTE_MAX_ETHPORTS, 1);
	if (peer_ports_len < 0) {
		DOCA_LOG_ERR("Failed to get hairpin peer Tx ports of port %d, (%d)",
				port_id,
				peer_ports_len);
		return DOCA_ERROR_DRIVER;
	}

	for (peer_port = 0; peer_port < peer_ports_len; peer_port++) {
		result = rte_eth_hairpin_unbind(port_id, peer_ports[peer_port]);
		if (result < 0) {
			DOCA_LOG_ERR("Failed to bind hairpin queues (%d)", result);
			return DOCA_ERROR_DRIVER;
		}
	}

	/* unbind all peer Tx from current Rx */
	peer_ports_len = rte_eth_hairpin_get_peer_ports(
			port_id, peer_ports, RTE_MAX_ETHPORTS, 0);
	if (peer_ports_len < 0) {
		DOCA_LOG_ERR("Failed to get hairpin peer Tx ports of port %d, (%d)",
				port_id,
				peer_ports_len);
		return DOCA_ERROR_DRIVER;
	}

	for (peer_port = 0; peer_port < peer_ports_len; peer_port++) {
		result = rte_eth_hairpin_unbind(peer_ports[peer_port], port_id);
		if (result < 0) {
			DOCA_LOG_ERR("Failed to bind hairpin queues (%d)", result);
			return DOCA_ERROR_DRIVER;
		}
	}
	return DOCA_SUCCESS;
}

/*
 * Set up all hairpin queues
 *
 * @port_id [in]: port ID
 * @peer_port_id [in]: peer port ID
 * @reserved_hairpin_q_list [in]: list of hairpin queues index
 * @hairpin_queue_len [in]: length of reserved_hairpin_q_list
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
setup_hairpin_queues(struct application_dpdk_config* app_config,
                     uint16_t port_id,
                     uint16_t peer_port_id,
                     uint16_t* reserved_hairpin_q_list,
                     int hairpin_queue_len)
{
	/* Port:
	* 0. RX queue
	*1. RX hairpin queue rte_eth_rx_hairpin_queue_setup
	*2. TX hairpin queue rte_eth_tx_hairpin_queue_setup
	*/

	int result = 0, hairpin_q;
	uint16_t nb_tx_rx_desc = 2048;
	uint32_t manual = 1;
	uint32_t tx_exp = 1;
	struct rte_eth_hairpin_conf hairpin_conf = {
		.peer_count = 1,
		.manual_bind = !!manual,
		.tx_explicit = !!tx_exp,
		.peers[0] = { peer_port_id, 0 },
	};

	DOCA_LOG_DBG("Setting up hairpin queues %d-%d for %u->%u",
			reserved_hairpin_q_list[0],
			reserved_hairpin_q_list[0] + hairpin_queue_len - 1,
			port_id,
			peer_port_id);

	app_config->hairpin_queues[port_id][peer_port_id] =
		reserved_hairpin_q_list[0];
	app_config->hairpin_q_count = hairpin_queue_len;

	for (hairpin_q = 0; hairpin_q < hairpin_queue_len; hairpin_q++) {
		// TX
		hairpin_conf.peers[0].queue = reserved_hairpin_q_list[hairpin_q];
		result =
			rte_eth_tx_hairpin_queue_setup(port_id,
						reserved_hairpin_q_list[hairpin_q],
						nb_tx_rx_desc,
						&hairpin_conf);
		if (result < 0) {
			DOCA_LOG_ERR("Failed to setup hairpin queues (%d)", result);
			return DOCA_ERROR_DRIVER;
		}

		// RX
		hairpin_conf.peers[0].queue = reserved_hairpin_q_list[hairpin_q];
		result =
			rte_eth_rx_hairpin_queue_setup(port_id,
					reserved_hairpin_q_list[hairpin_q],
					nb_tx_rx_desc,
					&hairpin_conf);
		if (result < 0) {
			DOCA_LOG_ERR("Failed to setup hairpin queues (%d)", result);
			return DOCA_ERROR_DRIVER;
		}
	}
	return DOCA_SUCCESS;
}

/*
 * Unbind hairpin queues from all ports
 *
 * @nb_ports [in]: number of ports
 */
static void
disable_hairpin_queues(uint16_t nb_ports)
{
    doca_error_t result;
    uint16_t port_id;

    for (port_id = 0; port_id < nb_ports; port_id++) {
        if (!rte_eth_dev_is_valid_port(port_id))
            continue;
        result = unbind_hairpin_queues(port_id);
        if (result != DOCA_SUCCESS)
            DOCA_LOG_ERR("Disabling hairpin queues failed: err=%d, port=%u",
                         result,
                         port_id);
    }
}

/*
 * Bind hairpin queues to all ports
 *
 * @nb_ports [in]: number of ports
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t enable_hairpin_queues(uint8_t nb_ports)
{
        uint16_t port_id;
        uint16_t n = 0;
        doca_error_t result;

        for (port_id = 0; port_id < RTE_MAX_ETHPORTS; port_id++) {
                if (!rte_eth_dev_is_valid_port(port_id))
                        /* the device ID  might not be contiguous */
                        continue;
                result = bind_hairpin_queues(port_id);
                if (result != DOCA_SUCCESS) {
                        DOCA_LOG_ERR("Hairpin bind failed on port=%u", port_id);
                        disable_hairpin_queues(port_id);
                        return result;
                }
                if (++n >= nb_ports)
                        break;
        }
        return DOCA_SUCCESS;
}

/*
 * Creates a new mempool in memory to hold the mbufs
 *
 * @total_nb_mbufs [in]: the number of elements in the mbuf pool
 * @mbuf_pool [out]: the allocated pool
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
allocate_mempool(const uint32_t total_nb_mbufs, struct rte_mempool** mbuf_pool)
{
    *mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL",
                                         total_nb_mbufs,
                                         MBUF_CACHE_SIZE,
                                         0,
                                         RTE_MBUF_DEFAULT_BUF_SIZE,
                                         rte_socket_id());
    if (*mbuf_pool == NULL) {
        DOCA_LOG_ERR("Cannot allocate mbuf pool");
        return DOCA_ERROR_DRIVER;
    }
    return DOCA_SUCCESS;
}

/*
 * Initialize all the port resources
 *
 * @mbuf_pool [in]: packet mbuf pool
 * @port [in]: the port ID
 * @app_config [in]: application DPDK configuration values
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
port_init(struct rte_mempool* mbuf_pool,
          uint8_t port,
          struct application_dpdk_config* app_config)
{
    doca_error_t result;
    int ret = 0;
    int symmetric_hash_key_length = RSS_KEY_LEN;
    const uint16_t nb_hairpin_queues = app_config->port_config.nb_hairpin_q;
    const uint16_t rx_rings = app_config->port_config.nb_queues;
    const uint16_t tx_rings = app_config->port_config.nb_queues;
    const uint16_t rss_support = !!(app_config->port_config.rss_support &&
                                    (app_config->port_config.nb_queues > 1));
    bool isolated = !!app_config->port_config.isolated_mode;
    uint16_t q, queue_index;
    struct rte_ether_addr addr;
    struct rte_eth_dev_info dev_info;
    struct rte_flow_error error;
    uint8_t symmetric_hash_key[RSS_KEY_LEN] = {
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    };
    const struct rte_eth_conf port_conf_default = {
      .lpbk_mode = app_config->port_config.lpbk_support,
      .rx_adv_conf =
          {
              .rss_conf =
                  {
                      .rss_key_len = symmetric_hash_key_length,
                      .rss_key = symmetric_hash_key,
                      .rss_hf =
                          (RTE_ETH_RSS_IP | RTE_ETH_RSS_UDP | RTE_ETH_RSS_TCP),
                  },
          },
  };
    struct rte_eth_conf port_conf = port_conf_default;

    ret = rte_eth_dev_info_get(port, &dev_info);
    if (ret < 0) {
        DOCA_LOG_ERR("Failed getting device (port %u) info, error=%s",
                     port,
                     strerror(-ret));
        return DOCA_ERROR_DRIVER;
    }
    if (*dev_info.dev_flags & RTE_ETH_DEV_REPRESENTOR &&
        app_config->port_config.switch_mode) {
        DOCA_LOG_INFO("Skip represent port %d init in switch mode", port);
        return DOCA_SUCCESS;
    }

    port_conf.rxmode.mq_mode =
        rss_support ? RTE_ETH_MQ_RX_RSS : RTE_ETH_MQ_RX_NONE;

    /* Configure the Ethernet device */
    ret = rte_eth_dev_configure(port,
                                rx_rings + nb_hairpin_queues,
                                tx_rings + nb_hairpin_queues,
                                &port_conf);
    if (ret < 0) {
        DOCA_LOG_ERR("Failed to configure the ethernet device - (%d)", ret);
        return DOCA_ERROR_DRIVER;
    }
    if (port_conf_default.rx_adv_conf.rss_conf.rss_hf !=
        port_conf.rx_adv_conf.rss_conf.rss_hf) {
        DOCA_LOG_DBG("Port %u modified RSS hash function based on hardware "
                     "support, requested:%#" PRIx64 " configured:%#" PRIx64 "",
                     port,
                     port_conf_default.rx_adv_conf.rss_conf.rss_hf,
                     port_conf.rx_adv_conf.rss_conf.rss_hf);
    }

    /* Enable RX in promiscuous mode for the Ethernet device */
    ret = rte_eth_promiscuous_enable(port);
    if (ret < 0) {
        DOCA_LOG_ERR("Failed to Enable RX in promiscuous mode - (%d)", ret);
        return DOCA_ERROR_DRIVER;
    }

    /* Allocate and set up RX queues according to number of cores per Ethernet
     * port */
    for (q = 0; q < rx_rings; q++) {
        ret = rte_eth_rx_queue_setup(port,
                                     q,
                                     RX_RING_SIZE,
                                     rte_eth_dev_socket_id(port),
                                     NULL,
                                     mbuf_pool);
        if (ret < 0) {
            DOCA_LOG_ERR("Failed to set up RX queues - (%d)", ret);
            return DOCA_ERROR_DRIVER;
        }
    }

    /* Allocate and set up TX queues according to number of cores per Ethernet
     * port */
    for (q = 0; q < tx_rings; q++) {
        ret = rte_eth_tx_queue_setup(
            port, q, TX_RING_SIZE, rte_eth_dev_socket_id(port), NULL);
        if (ret < 0) {
            DOCA_LOG_ERR("Failed to set up TX queues - (%d)", ret);
            return DOCA_ERROR_DRIVER;
        }
    }

    /* Enabled hairpin queue before port start */
    if (nb_hairpin_queues) {
        uint16_t rss_queue_list[nb_hairpin_queues];

        if (app_config->port_config.self_hairpin &&
            rte_eth_dev_is_valid_port(port ^ 1)) {
            /* Hairpin to both self and peer */
            assert((nb_hairpin_queues % 2) == 0);
            for (queue_index = 0; queue_index < nb_hairpin_queues / 2;
                 queue_index++)
                rss_queue_list[queue_index] =
                    app_config->port_config.nb_queues + queue_index;
            result = setup_hairpin_queues(
                app_config, port, port, rss_queue_list, nb_hairpin_queues / 2);
            if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("Cannot hairpin self port %" PRIu8 ", ret: %s",
                             port,
                             doca_error_get_descr(result));
                return result;
            }
            for (queue_index = 0; queue_index < nb_hairpin_queues / 2;
                 queue_index++)
                rss_queue_list[queue_index] =
                    app_config->port_config.nb_queues +
                    (nb_hairpin_queues / 2) + queue_index;
            result = setup_hairpin_queues(app_config,
                                          port,
                                          port ^ 1,
                                          rss_queue_list,
                                          nb_hairpin_queues / 2);
            if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("Cannot hairpin peer port %" PRIu8 ", ret: %s",
                             port ^ 1,
                             doca_error_get_descr(result));
                return result;
            }
        } else {
            /* Hairpin to self or peer */
            for (queue_index = 0; queue_index < nb_hairpin_queues;
                 queue_index++)
                rss_queue_list[queue_index] =
                    app_config->port_config.nb_queues + queue_index;
            if (rte_eth_dev_is_valid_port(port ^ 1))
                result = setup_hairpin_queues(app_config,
                                              port,
                                              port ^ 1,
                                              rss_queue_list,
                                              nb_hairpin_queues);
            else
                result = setup_hairpin_queues(
                    app_config, port, port, rss_queue_list, nb_hairpin_queues);
            if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR(
                    "Cannot hairpin port %" PRIu8 ", ret=%d", port, result);
                return result;
            }
        }
    }

    /* Set isolated mode (true or false) before port start */
    ret = rte_flow_isolate(port, isolated, &error);
    if (ret < 0) {
        DOCA_LOG_ERR("Port %u could not be set isolated mode to %s (%s)",
                     port,
                     isolated ? "true" : "false",
                     error.message);
        return DOCA_ERROR_DRIVER;
    }
    if (isolated)
        DOCA_LOG_INFO("Ingress traffic on port %u is in isolated mode", port);

    /* Start the Ethernet port */
    ret = rte_eth_dev_start(port);
    if (ret < 0) {
        DOCA_LOG_ERR("Cannot start port %" PRIu8 ", ret=%d", port, ret);
        return DOCA_ERROR_DRIVER;
    }

    /* Display the port MAC address */
    rte_eth_macaddr_get(port, &addr);
    DOCA_LOG_DBG("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8
                 " %02" PRIx8 " %02" PRIx8 "",
                 (unsigned int)port,
                 addr.addr_bytes[0],
                 addr.addr_bytes[1],
                 addr.addr_bytes[2],
                 addr.addr_bytes[3],
                 addr.addr_bytes[4],
                 addr.addr_bytes[5]);

    /*
     * Check that the port is on the same NUMA node as the polling thread
     * for best performance.
     */
    if (rte_eth_dev_socket_id(port) > 0 &&
        rte_eth_dev_socket_id(port) != (int)rte_socket_id()) {
        DOCA_LOG_WARN("Port %u is on remote NUMA node to polling thread", port);
        DOCA_LOG_WARN("\tPerformance will not be optimal");
    }
    return DOCA_SUCCESS;
}

/*
 * Destroy all DPDK ports
 *
 * @app_dpdk_config [in]: application DPDK configuration values
 * @nb_ports [in]: number of ports to destroy
 */
static void
dpdk_ports_fini(struct application_dpdk_config* app_dpdk_config,
                uint16_t nb_ports)
{
    int result;
    int port_id;

    for (port_id = nb_ports; port_id >= 0; port_id--) {
        if (!rte_eth_dev_is_valid_port(port_id))
            continue;
        result = rte_eth_dev_stop(port_id);
        if (result != 0)
            DOCA_LOG_ERR(
                "rte_eth_dev_stop(): err=%d, port=%u", result, port_id);

        result = rte_eth_dev_close(port_id);
        if (result != 0)
            DOCA_LOG_ERR(
                "rte_eth_dev_close(): err=%d, port=%u", result, port_id);
    }

    /* Free the memory pool used by the ports for rte_pktmbufs */
    if (app_dpdk_config->mbuf_pool != NULL)
        rte_mempool_free(app_dpdk_config->mbuf_pool);
}

/*
 * Initialize all DPDK ports
 *
 * @app_config [in]: application DPDK configuration values
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
dpdk_ports_init(struct application_dpdk_config* app_config)
{
    doca_error_t result;
    int ret;
    uint16_t port_id;
    uint16_t n;
    const uint16_t nb_ports = app_config->port_config.nb_ports;
    const uint32_t total_nb_mbufs =
        app_config->port_config.nb_queues * nb_ports * NUM_MBUFS;

    /* Initialize mbufs mempool */
    result = allocate_mempool(total_nb_mbufs, &app_config->mbuf_pool);
    if (result != DOCA_SUCCESS)
        return result;

    /*
     * Enable metadata to be delivered to application in the packets mbuf, the
     * metadata is user configurable, with DOCA Flow offering a metadata scheme
     */
    if (app_config->port_config.enable_mbuf_metadata) {
        ret = rte_flow_dynf_metadata_register();
        if (ret < 0) {
            DOCA_LOG_ERR("Metadata register failed, ret=%d", ret);
            return DOCA_ERROR_DRIVER;
        }
    }

    for (port_id = 0, n = 0; port_id < RTE_MAX_ETHPORTS; port_id++) {
        if (!rte_eth_dev_is_valid_port(port_id))
            continue;
        result = port_init(app_config->mbuf_pool, port_id, app_config);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Cannot init port %" PRIu8, port_id);
            dpdk_ports_fini(app_config, port_id);
            return result;
        }
        if (++n >= nb_ports)
            break;
    }
    return DOCA_SUCCESS;
}

doca_error_t dpdk_queues_and_ports_init(struct application_dpdk_config *app_dpdk_config)
{
        doca_error_t result;
        int ret = 0;

        /* Check that DPDK enabled the required ports to send/receive on */
        ret = rte_eth_dev_count_avail();
        if (app_dpdk_config->port_config.nb_ports > 0 && ret < app_dpdk_config->port_config.nb_ports) {
                DOCA_LOG_ERR("Application will only function with %u ports, num_of_ports=%d",
                             app_dpdk_config->port_config.nb_ports,
                             ret);
                return DOCA_ERROR_DRIVER;
        }

        /* Check for available logical cores */
        ret = rte_lcore_count();
        if (app_dpdk_config->port_config.nb_queues > 0 && ret < app_dpdk_config->port_config.nb_queues) {
                DOCA_LOG_ERR("At least %u cores are needed for the application to run, available_cores=%d",
                             app_dpdk_config->port_config.nb_queues,
                             ret);
                return DOCA_ERROR_DRIVER;
        }
        app_dpdk_config->port_config.nb_queues = ret;

        if (app_dpdk_config->reserve_main_thread)
                app_dpdk_config->port_config.nb_queues -= 1;

        if (app_dpdk_config->port_config.nb_ports > 0) {
                result = dpdk_ports_init(app_dpdk_config);
                if (result != DOCA_SUCCESS) {
                        DOCA_LOG_ERR("Ports allocation failed");
                        return result;
                }
        }

        /* Enable hairpin queues */
        if (app_dpdk_config->port_config.nb_hairpin_q > 0) {
                result = enable_hairpin_queues(app_dpdk_config->port_config.nb_ports);
                if (result != DOCA_SUCCESS)
                        goto ports_cleanup;
        }

        return DOCA_SUCCESS;

ports_cleanup:
        dpdk_ports_fini(app_dpdk_config, RTE_MAX_ETHPORTS);
        return result;
}

void
dpdk_queues_and_ports_fini(struct application_dpdk_config* app_dpdk_config)
{
    disable_hairpin_queues(RTE_MAX_ETHPORTS);

    dpdk_ports_fini(app_dpdk_config, RTE_MAX_ETHPORTS);
}
doca_error_t
dpdk_init(int argc, char** argv)
{
    int result;

    result = rte_eal_init(argc, argv);
    if (result < 0) {
        DOCA_LOG_ERR("EAL initialization failed");
        return DOCA_ERROR_DRIVER;
    }
    return DOCA_SUCCESS;
}

void
dpdk_fini(void)
{
    int result;

    result = rte_eal_cleanup();
    if (result < 0) {
        DOCA_LOG_ERR("rte_eal_cleanup() failed, error=%d", result);
        return;
    }

    DOCA_LOG_DBG("DPDK fini is done");
}
