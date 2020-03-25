/*
 * Copyright (c) 2011-2018 The Linux Foundation. All rights reserved.
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

#if !defined(__SMEINTERNAL_H)
#define __SMEINTERNAL_H

/**
 * \file  sme_internal.h
 *
 * \brief prototype for SME internal structures and APIs used for SME and MAC
 */

/*--------------------------------------------------------------------------
  Include Files
  ------------------------------------------------------------------------*/
#include "qdf_status.h"
#include "qdf_lock.h"
#include "qdf_trace.h"
#include "qdf_mem.h"
#include "qdf_types.h"
#include "host_diag_core_event.h"
#include "csr_link_list.h"
#include "sme_power_save.h"
#include "nan_api.h"
#include "wmi_unified.h"

struct wmi_twt_enable_complete_event_param;
/*--------------------------------------------------------------------------
  Type declarations
  ------------------------------------------------------------------------*/

/* Mask can be only have one bit set */
typedef enum eSmeCommandType {
	eSmeNoCommand = 0,
	/* this is not a command, it is to identify this is a CSR command */
	eSmeCsrCommandMask = 0x10000,
	eSmeCommandRoam,
	eSmeCommandWmStatusChange,
	e_sme_command_del_sta_session,
	/* QOS */
	eSmeQosCommandMask = 0x40000,   /* To identify Qos commands */
	eSmeCommandAddTs,
	eSmeCommandDelTs,
	e_sme_command_set_hw_mode,
	e_sme_command_nss_update,
	e_sme_command_set_dual_mac_config,
	e_sme_command_set_antenna_mode,
} eSmeCommandType;

typedef enum eSmeState {
	SME_STATE_STOP,
	SME_STATE_START,
	SME_STATE_READY,
} eSmeState;

#define SME_IS_START(pMac)  (SME_STATE_STOP != (pMac)->sme.state)
#define SME_IS_READY(pMac)  (SME_STATE_READY == (pMac)->sme.state)

/* HDD Callback function */
typedef void (*pIbssPeerInfoCb)(void *pUserData,
					tSirPeerInfoRspParams *infoParam);

/* Peer info */
typedef struct tagSmePeerInfoHddCbkInfo {
	void *pUserData;
	pIbssPeerInfoCb peerInfoCbk;
} tSmePeerInfoHddCbkInfo;

typedef struct sStatsExtEvent {
	uint32_t vdev_id;
	uint32_t event_data_len;
	uint8_t event_data[];
} tStatsExtEvent, *tpStatsExtEvent;

#define MAX_ACTIVE_CMD_STATS    16

typedef struct sActiveCmdStats {
	eSmeCommandType command;
	uint32_t reason;
	uint32_t sessionId;
	uint64_t timestamp;
} tActiveCmdStats;

typedef struct sSelfRecoveryStats {
	tActiveCmdStats activeCmdStats[MAX_ACTIVE_CMD_STATS];
	uint8_t cmdStatsIndx;
} tSelfRecoveryStats;

typedef void (*ocb_callback)(void *context, void *response);
typedef void (*sme_set_thermal_level_callback)(hdd_handle_t hdd_handle,
					       u_int8_t level);
typedef void (*p2p_lo_callback)(void *context,
				struct sir_p2p_lo_event *event);
#ifdef FEATURE_OEM_DATA_SUPPORT
typedef void (*sme_send_oem_data_rsp_msg)(struct oem_data_rsp *);
#endif

#ifdef FEATURE_WLAN_APF
/**
 * typedef apf_get_offload_cb - APF offload callback signature
 * @context: Opaque context that the client can use to associate the
 *    callback with the request
 * @caps: APF offload capabilities as reported by firmware
 */
struct sir_apf_get_offload;
typedef void (*apf_get_offload_cb)(void *context,
				   struct sir_apf_get_offload *caps);

/**
 * typedef apf_read_mem_cb - APF read memory response callback
 * @context: Opaque context that the client can use to associate the
 *    callback with the request
 * @evt: APF read memory response event parameters
 */
typedef void (*apf_read_mem_cb)(void *context,
				struct wmi_apf_read_memory_resp_event_params
									  *evt);
#endif /* FEATURE_WLAN_APF */

/**
 * typedef sme_encrypt_decrypt_callback - encrypt/decrypt callback
 *    signature
 * @context: Opaque context that the client can use to associate the
 *    callback with the request
 * @response: Encrypt/Decrypt response from firmware
 */
struct sir_encrypt_decrypt_rsp_params;
typedef void (*sme_encrypt_decrypt_callback)(
			void *context,
			struct sir_encrypt_decrypt_rsp_params *response);

/**
 * typedef get_chain_rssi_callback - get chain rssi callback
 * @context: Opaque context that the client can use to associate the
 *    callback with the request
 * @data: chain rssi result reported by firmware
 */
struct chain_rssi_result;
typedef void (*get_chain_rssi_callback)(void *context,
					struct chain_rssi_result *data);

/**
 * typedef pwr_save_fail_cb - power save fail callback function
 * @hdd_handle: HDD handle registered with SME
 * @params: failure parameters
 */
struct chip_pwr_save_fail_detected_params;
typedef void (*pwr_save_fail_cb)(hdd_handle_t hdd_handle,
			struct chip_pwr_save_fail_detected_params *params);

/**
 * typedef bt_activity_info_cb - bluetooth activity callback function
 * @hdd_handle: HDD handle registered with SME
 * @bt_activity: bluetooth activity information
 */
typedef void (*bt_activity_info_cb)(hdd_handle_t hdd_handle,
				    uint32_t bt_activity);

/**
 * typedef congestion_cb - congestion callback function
 * @hdd_handle: HDD handle registered with SME
 * @congestion: Current congestion value
 * @vdev_id: ID of the vdev for which congestion is being reported
 */
typedef void (*congestion_cb)(hdd_handle_t hdd_handle, uint32_t congestion,
			      uint32_t vdev_id);

/**
 * typedef rso_cmd_status_cb - RSO command status  callback function
 * @hdd_handle: HDD handle registered with SME
 * @rso_status: Status of the operation
 */
typedef void (*rso_cmd_status_cb)(hdd_handle_t hdd_handle,
				  struct rso_cmd_status *rso_status);

/**
 * typedef lost_link_info_cb - lost link indication callback function
 * @hdd_handle: HDD handle registered with SME
 * @lost_link_info: Information about the lost link
 */
typedef void (*lost_link_info_cb)(hdd_handle_t hdd_handle,
				  struct sir_lost_link_info *lost_link_info);
/**
 * typedef hidden_ssid_cb - hidden ssid rsp callback fun
 * @hdd_handle: HDD handle registered with SME
 * @vdev_id: Vdev Id
 */
typedef void (*hidden_ssid_cb)(hdd_handle_t hdd_handle,
				uint8_t vdev_id);

/**
 * typedef sme_get_isolation_cb - get isolation callback fun
 * @param: isolation result reported by firmware
 * @pcontext: Opaque context that the client can use to associate the
 *    callback with the request
 */
typedef void (*sme_get_isolation_cb)(struct sir_isolation_resp *param,
				     void *pcontext);

typedef struct tagSmeStruct {
	eSmeState state;
	qdf_mutex_t lkSmeGlobalLock;
	uint32_t totalSmeCmd;
	/* following pointer contains array of pointers for tSmeCmd* */
	void **pSmeCmdBufAddr;
	tDblLinkList smeCmdFreeList;    /* preallocated roam cmd list */
	enum QDF_OPMODE currDeviceMode;
	tSmePeerInfoHddCbkInfo peerInfoParams;
#ifdef FEATURE_WLAN_DIAG_SUPPORT_CSR
	host_event_wlan_status_payload_type eventPayload;
#endif
#ifdef WLAN_FEATURE_LINK_LAYER_STATS
	void *ll_stats_context;
	void (*pLinkLayerStatsIndCallback)(void *callback_ctx, int ind_type,
					   void *rsp, void *context);
	void (*link_layer_stats_ext_cb)(hdd_handle_t callback_ctx,
					tSirLLStatsResults *rsp);
#endif /* WLAN_FEATURE_LINK_LAYER_STATS */

#ifdef WLAN_POWER_DEBUGFS
	void *power_debug_stats_context;
	void (*power_stats_resp_callback)(struct power_stats_response *rsp,
						void *callback_context);
#endif
#ifdef WLAN_FEATURE_BEACON_RECEPTION_STATS
	void *beacon_stats_context;
	void (*beacon_stats_resp_callback)(struct bcn_reception_stats_rsp *rsp,
					   void *callback_context);
#endif
#ifdef FEATURE_WLAN_AUTO_SHUTDOWN
	void (*pAutoShutdownNotificationCb)(void);
#endif
	/* Maximum interfaces allowed by the host */
	uint8_t max_intf_count;
	void (*StatsExtCallback)(void *, tStatsExtEvent *);
	/* linkspeed callback */
	void (*pLinkSpeedIndCb)(tSirLinkSpeedInfo *indParam,
			void *pDevContext);
	void *pLinkSpeedCbContext;
	/* get peer info callback */
	void (*pget_peer_info_ind_cb)(struct sir_peer_info_resp *param,
		void *pcontext);
	void *pget_peer_info_cb_context;
	/* get extended peer info callback */
	void (*pget_peer_info_ext_ind_cb)(struct sir_peer_info_ext_resp *param,
		void *pcontext);
	void *pget_peer_info_ext_cb_context;
	sme_get_isolation_cb get_isolation_cb;
	void *get_isolation_cb_context;
#ifdef FEATURE_WLAN_EXTSCAN
	void (*pExtScanIndCb)(void *, const uint16_t, void *);
#endif /* FEATURE_WLAN_EXTSCAN */
#ifdef WLAN_FEATURE_NAN
	nan_callback nan_callback;
#endif
	bool enableSelfRecovery;
	csr_link_status_callback link_status_callback;
	void *link_status_context;
	int (*get_tsf_cb)(void *pcb_cxt, struct stsf *ptsf);
	void *get_tsf_cxt;
	/* get temperature event context and callback */
	void *pTemperatureCbContext;
	void (*pGetTemperatureCb)(int temperature, void *context);
	uint8_t miracast_value;
	struct ps_global_info  ps_global_info;
	void (*rssi_threshold_breached_cb)(void *, struct rssi_breach_event *);
	hw_mode_transition_cb sme_hw_mode_trans_cb;
	sme_set_thermal_level_callback set_thermal_level_cb;
	void *apf_get_offload_context;
	p2p_lo_callback p2p_lo_event_callback;
	void *p2p_lo_event_context;
#ifdef FEATURE_OEM_DATA_SUPPORT
	sme_send_oem_data_rsp_msg oem_data_rsp_callback;
#endif
	sme_encrypt_decrypt_callback encrypt_decrypt_cb;
	void *encrypt_decrypt_context;
	lost_link_info_cb lost_link_info_cb;

	bool (*set_connection_info_cb)(bool);
	bool (*get_connection_info_cb)(uint8_t *session_id,
			enum scan_reject_states *reason);
	rso_cmd_status_cb rso_cmd_status_cb;
	congestion_cb congestion_cb;
	void (*stats_ext2_cb)(void *, struct sir_sme_rx_aggr_hole_ind *);
	pwr_save_fail_cb chip_power_save_fail_cb;
	bt_activity_info_cb bt_activity_info_cb;
	void *get_arp_stats_context;
	void (*get_arp_stats_cb)(void *, struct rsp_stats *, void *);
	get_chain_rssi_callback get_chain_rssi_cb;
	void *get_chain_rssi_context;
	void (*tx_queue_cb)(void *, uint32_t vdev_id,
			    enum netif_action_type action,
			    enum netif_reason_type reason);
	void (*twt_enable_cb)(void *hdd_ctx,
			struct wmi_twt_enable_complete_event_param *params);
	void (*twt_disable_cb)(void *hdd_ctx);
#ifdef FEATURE_WLAN_APF
	apf_get_offload_cb apf_get_offload_cb;
	apf_read_mem_cb apf_read_mem_cb;
#endif
	/* hidden ssid rsp callback */
	hidden_ssid_cb hidden_ssid_cb;

#ifdef WLAN_MWS_INFO_DEBUGFS
	void *mws_coex_info_ctx;
	void (*mws_coex_info_state_resp_callback)(void *coex_info_data,
						  void *context,
						  wmi_mws_coex_cmd_id cmd_id);
#endif /* WLAN_MWS_INFO_DEBUGFS */
} tSmeStruct, *tpSmeStruct;

#endif /* #if !defined( __SMEINTERNAL_H ) */
