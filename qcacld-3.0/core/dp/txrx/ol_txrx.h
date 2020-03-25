/*
 * Copyright (c) 2012-2018 The Linux Foundation. All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for
 * any purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all
 * copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 * TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _OL_TXRX__H_
#define _OL_TXRX__H_

#include <qdf_nbuf.h>           /* qdf_nbuf_t */
#include <cdp_txrx_cmn.h>       /* ol_txrx_vdev_t, etc. */
#include "cds_sched.h"
#include <cdp_txrx_handle.h>
#include <ol_txrx_types.h>
/*
 * Pool of tx descriptors reserved for
 * high-priority traffic, such as ARP/EAPOL etc
 * only for forwarding path.
 */
#define OL_TX_NON_FWD_RESERVE	100

#define TXRX_RFS_ENABLE_PEER_ID_UNMAP_COUNT    3
#define TXRX_RFS_DISABLE_PEER_ID_UNMAP_COUNT   1

ol_txrx_peer_handle ol_txrx_peer_get_ref_by_addr(ol_txrx_pdev_handle pdev,
						 u8 *peer_addr,
						 u8 *peer_id,
						 enum peer_debug_id_type
									dbg_id);

int  ol_txrx_peer_release_ref(ol_txrx_peer_handle peer,
			      enum peer_debug_id_type dbg_id);

/**
 * ol_tx_desc_pool_size_hl() - allocate tx descriptor pool size for HL systems
 * @ctrl_pdev: the control pdev handle
 *
 * Return: allocated pool size
 */
u_int16_t
ol_tx_desc_pool_size_hl(struct cdp_cfg *ctrl_pdev);

#ifndef OL_TX_AVG_FRM_BYTES
#define OL_TX_AVG_FRM_BYTES 1000
#endif

#ifndef OL_TX_DESC_POOL_SIZE_MIN_HL
#define OL_TX_DESC_POOL_SIZE_MIN_HL 500
#endif

#ifndef OL_TX_DESC_POOL_SIZE_MAX_HL
#define OL_TX_DESC_POOL_SIZE_MAX_HL 5000
#endif

#ifndef FW_STATS_DESC_POOL_SIZE
#define FW_STATS_DESC_POOL_SIZE 10
#endif

#ifdef CONFIG_PER_VDEV_TX_DESC_POOL
#define TXRX_HL_TX_FLOW_CTRL_VDEV_LOW_WATER_MARK 400
#define TXRX_HL_TX_FLOW_CTRL_MGMT_RESERVED 100
#endif

#ifdef CONFIG_TX_DESC_HI_PRIO_RESERVE
#define TXRX_HL_TX_DESC_HI_PRIO_RESERVED 20
#endif

#if defined(CONFIG_HL_SUPPORT) && defined(FEATURE_WLAN_TDLS)

void
ol_txrx_hl_tdls_flag_reset(struct cdp_vdev *vdev, bool flag);
#else

static inline void
ol_txrx_hl_tdls_flag_reset(struct cdp_vdev *vdev, bool flag)
{
}
#endif

#ifdef WDI_EVENT_ENABLE
void *ol_get_pldev(struct cdp_pdev *txrx_pdev);
#else
static inline
void *ol_get_pldev(struct cdp_pdev *txrx_pdev)
{
	return NULL;
}
#endif
/*
 * @nbuf: buffer which contains data to be displayed
 * @nbuf_paddr: physical address of the buffer
 * @len: defines the size of the data to be displayed
 *
 * Return: None
 */
void
ol_txrx_dump_pkt(qdf_nbuf_t nbuf, uint32_t nbuf_paddr, int len);

/**
 * ol_txrx_fwd_desc_thresh_check() - check to forward packet to tx path
 * @vdev: which virtual device the frames were addressed to
 *
 * This API is to check whether enough descriptors are available or not
 * to forward packet to tx path. If not enough descriptors left,
 * start dropping tx-path packets.
 * Do not pause netif queues as still a pool of descriptors is reserved
 * for high-priority traffic such as EAPOL/ARP etc.
 * In case of intra-bss forwarding, it could be possible that tx-path can
 * consume all the tx descriptors and pause netif queues. Due to this,
 * there would be some left for stack triggered packets such as ARP packets
 * which could lead to disconnection of device. To avoid this, reserved
 * a pool of descriptors for high-priority packets, i.e., reduce the
 * threshold of drop in the intra-bss forwarding path.
 *
 * Return: true ; forward the packet, i.e., below threshold
 *         false; not enough descriptors, drop the packet
 */
bool ol_txrx_fwd_desc_thresh_check(struct ol_txrx_vdev_t *vdev);

struct cdp_vdev *ol_txrx_get_vdev_from_vdev_id(uint8_t vdev_id);

void *ol_txrx_find_peer_by_addr(struct cdp_pdev *pdev,
				uint8_t *peer_addr,
				uint8_t *peer_id);

void htt_pkt_log_init(struct cdp_pdev *pdev_handle, void *scn);
void peer_unmap_timer_work_function(void *);
void peer_unmap_timer_handler(void *data);

int ol_txrx_fw_stats_desc_pool_init(struct ol_txrx_pdev_t *pdev,
				    uint8_t pool_size);
void ol_txrx_fw_stats_desc_pool_deinit(struct ol_txrx_pdev_t *pdev);
struct ol_txrx_fw_stats_desc_t
	*ol_txrx_fw_stats_desc_alloc(struct ol_txrx_pdev_t *pdev);
struct ol_txrx_stats_req_internal
	*ol_txrx_fw_stats_desc_get_req(struct ol_txrx_pdev_t *pdev,
				       uint8_t desc_id);

/**
 * ol_txrx_get_new_htt_msg_format() - check htt h2t msg feature
 * @pdev - datapath device instance
 *
 * Check if h2t message length includes htc header length
 *
 * return if new htt h2t msg feature enabled
 */
bool ol_txrx_get_new_htt_msg_format(struct ol_txrx_pdev_t *pdev);

/**
 * ol_txrx_set_new_htt_msg_format() - set htt h2t msg feature
 * @val - enable or disable new htt h2t msg feature
 *
 * Set if h2t message length includes htc header length
 *
 * return NONE
 */
void ol_txrx_set_new_htt_msg_format(uint8_t val);

/**
 * ol_txrx_set_peer_unmap_conf_support() - set peer unmap conf feature
 * @val - enable or disable peer unmap conf feature
 *
 * Set if peer unamp conf feature is supported by both FW and in INI
 *
 * return NONE
 */
void ol_txrx_set_peer_unmap_conf_support(bool val);

/**
 * ol_txrx_get_peer_unmap_conf_support() - check peer unmap conf feature
 *
 * Check if peer unmap conf feature is enabled
 *
 * return true is peer unmap conf feature is enabled else false
 */
bool ol_txrx_get_peer_unmap_conf_support(void);

/**
 * ol_txrx_get_tx_compl_tsf64() - check tx compl tsf64 feature
 *
 * Check if tx compl tsf64 feature is enabled
 *
 * return true is tx compl tsf64 feature is enabled else false
 */
bool ol_txrx_get_tx_compl_tsf64(void);

/**
 * ol_txrx_set_tx_compl_tsf64() - set tx compl tsf64 feature
 * @val - enable or disable tx compl tsf64 feature
 *
 * Set if tx compl tsf64 feature is supported FW
 *
 * return NONE
 */
void ol_txrx_set_tx_compl_tsf64(bool val);
#endif /* _OL_TXRX__H_ */
