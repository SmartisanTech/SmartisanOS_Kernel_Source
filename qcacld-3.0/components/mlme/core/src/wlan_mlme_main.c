/*
 * Copyright (c) 2018-2019 The Linux Foundation. All rights reserved.
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
/**
 * DOC: define internal APIs related to the mlme component
 */
#include "wlan_mlme_main.h"
#include "wmi_unified.h"
#include "wlan_utility.h"
#include "wma_types.h"
#include "wma.h"
#include "wma_internal.h"

struct vdev_mlme_priv_obj *
wlan_vdev_mlme_get_priv_obj(struct wlan_objmgr_vdev *vdev)
{
	struct vdev_mlme_priv_obj *vdev_mlme;

	if (!vdev) {
		mlme_err("vdev is NULL");
		return NULL;
	}

	vdev_mlme = wlan_objmgr_vdev_get_comp_private_obj(vdev,
							  WLAN_UMAC_COMP_MLME);
	if (!vdev_mlme) {
		mlme_err(" MLME component object is NULL");
		return NULL;
	}

	return vdev_mlme;
}

struct mlme_nss_chains *mlme_get_dynamic_vdev_config(
				struct wlan_objmgr_vdev *vdev)
{
	struct vdev_mlme_priv_obj *vdev_mlme;

	vdev_mlme = wlan_vdev_mlme_get_priv_obj(vdev);
	if (!vdev_mlme) {
		mlme_err("vdev component object is NULL");
		return NULL;
	}

	return &vdev_mlme->dynamic_cfg;
}

/**
 * wlan_mlme_send_oce_flags_fw() - Send the oce flags to FW
 * @pdev: pointer to pdev object
 * @object: vdev object
 * @arg: Arguments to the handler
 *
 * Return: void
 */
static void wlan_mlme_send_oce_flags_fw(struct wlan_objmgr_pdev *pdev,
					void *object, void *arg)
{
	struct wlan_objmgr_vdev *vdev = object;
	uint8_t *updated_fw_value = arg;
	uint8_t *dynamic_fw_value = 0;
	uint8_t vdev_id;
	struct vdev_mlme_priv_obj *vdev_mlme;

	if (wlan_vdev_mlme_get_opmode(vdev) == QDF_STA_MODE) {
		vdev_mlme = wlan_vdev_mlme_get_priv_obj(vdev);
		if (!vdev_mlme) {
			mlme_err("vdev component object is NULL");
			return;
		}
		dynamic_fw_value = &vdev_mlme->sta_dynamic_oce_value;
		if (*updated_fw_value == *dynamic_fw_value) {
			mlme_debug("Current FW flags matches with updated value.");
			return;
		}
		*dynamic_fw_value = *updated_fw_value;
		vdev_id = wlan_vdev_get_id(vdev);
		if (wma_cli_set_command(vdev_id,
					WMI_VDEV_PARAM_ENABLE_DISABLE_OCE_FEATURES,
					*updated_fw_value, VDEV_CMD))
			mlme_err("Failed to send OCE update to FW");
	}
}

void wlan_mlme_update_oce_flags(struct wlan_objmgr_pdev *pdev,
				uint8_t cfg_value)
{
	uint16_t sap_connected_peer, go_connected_peer;
	struct wlan_objmgr_psoc *psoc = NULL;
	uint8_t updated_fw_value = 0;

	psoc = wlan_pdev_get_psoc(pdev);
	if (!psoc)
		return;
	sap_connected_peer =
	wlan_util_get_peer_count_for_mode(pdev, QDF_SAP_MODE);
	go_connected_peer =
	wlan_util_get_peer_count_for_mode(pdev, QDF_P2P_GO_MODE);

	if (sap_connected_peer || go_connected_peer) {
		updated_fw_value = cfg_value;
		updated_fw_value &=
		~(WMI_VDEV_OCE_PROBE_REQUEST_RATE_FEATURE_BITMAP);
		updated_fw_value &=
		~(WMI_VDEV_OCE_PROBE_REQUEST_DEFERRAL_FEATURE_BITMAP);
		mlme_debug("Disable STA OCE probe req rate and defferal updated_fw_value :%d",
			   updated_fw_value);
	} else {
		updated_fw_value = cfg_value;
		mlme_debug("Update the STA OCE flags to default INI updated_fw_value :%d",
			   updated_fw_value);
	}
	wlan_objmgr_pdev_iterate_obj_list(pdev, WLAN_VDEV_OP,
				wlan_mlme_send_oce_flags_fw,
				&updated_fw_value, 0, WLAN_MLME_NB_ID);
}

struct mlme_nss_chains *mlme_get_ini_vdev_config(
				struct wlan_objmgr_vdev *vdev)
{
	struct vdev_mlme_priv_obj *vdev_mlme;

	vdev_mlme = wlan_vdev_mlme_get_priv_obj(vdev);
	if (!vdev_mlme) {
		mlme_err("vdev component object is NULL");
		return NULL;
	}

	return &vdev_mlme->ini_cfg;
}

QDF_STATUS
mlme_vdev_object_created_notification(struct wlan_objmgr_vdev *vdev,
				      void *arg)
{
	struct vdev_mlme_priv_obj *vdev_mlme;
	QDF_STATUS status;

	if (!vdev) {
		mlme_err(" VDEV is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	vdev_mlme = qdf_mem_malloc(sizeof(*vdev_mlme));
	if (!vdev_mlme) {
		mlme_err(" MLME component object alloc failed");
		return QDF_STATUS_E_NOMEM;
	}

	status = wlan_objmgr_vdev_component_obj_attach(vdev,
						       WLAN_UMAC_COMP_MLME,
						       (void *)vdev_mlme,
						       QDF_STATUS_SUCCESS);

	if (QDF_IS_STATUS_ERROR(status)) {
		mlme_err("unable to attach vdev priv obj to vdev obj");
		qdf_mem_free(vdev_mlme);
	}

	return status;
}

QDF_STATUS
mlme_vdev_object_destroyed_notification(struct wlan_objmgr_vdev *vdev,
					void *arg)
{
	struct vdev_mlme_priv_obj *vdev_mlme;
	QDF_STATUS status;

	if (!vdev) {
		mlme_err(" VDEV is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	vdev_mlme = wlan_objmgr_vdev_get_comp_private_obj(vdev,
							  WLAN_UMAC_COMP_MLME);
	if (!vdev_mlme) {
		mlme_err(" VDEV MLME component object is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	status = wlan_objmgr_vdev_component_obj_detach(vdev,
						       WLAN_UMAC_COMP_MLME,
						       vdev_mlme);

	if (QDF_IS_STATUS_ERROR(status))
		mlme_err("unable to detach vdev priv obj to vdev obj");

	qdf_mem_free(vdev_mlme);

	return status;
}

QDF_STATUS mlme_get_peer_mic_len(struct wlan_objmgr_psoc *psoc, uint8_t pdev_id,
				 uint8_t *peer_mac, uint8_t *mic_len,
				 uint8_t *mic_hdr_len)
{
	struct wlan_objmgr_peer *peer;
	uint32_t key_cipher;

	if (!psoc || !mic_len || !mic_hdr_len || !peer_mac) {
		mlme_debug("psoc/mic_len/mic_hdr_len/peer_mac null");
		return QDF_STATUS_E_NULL_VALUE;
	}

	peer = wlan_objmgr_get_peer(psoc, pdev_id,
				    peer_mac, WLAN_LEGACY_MAC_ID);
	if (!peer) {
		mlme_debug("Peer of peer_mac %pM not found", peer_mac);
		return QDF_STATUS_E_INVAL;
	}
	key_cipher = wlan_peer_get_unicast_cipher(peer);
	wlan_objmgr_peer_release_ref(peer, WLAN_LEGACY_MAC_ID);

	if (key_cipher == WMI_CIPHER_AES_GCM) {
		*mic_hdr_len = WLAN_IEEE80211_GCMP_HEADERLEN;
		*mic_len = WLAN_IEEE80211_GCMP_MICLEN;
	} else {
		*mic_hdr_len = IEEE80211_CCMP_HEADERLEN;
		*mic_len = IEEE80211_CCMP_MICLEN;
	}
	mlme_debug("peer %pM hdr_len %d mic_len %d key_cipher %d", peer_mac,
		   *mic_hdr_len, *mic_len, key_cipher);

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
mlme_peer_object_created_notification(struct wlan_objmgr_peer *peer,
				      void *arg)
{
	struct peer_mlme_priv_obj *peer_priv;
	QDF_STATUS status;

	if (!peer) {
		mlme_err(" peer is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	peer_priv = qdf_mem_malloc(sizeof(*peer_priv));
	if (!peer_priv) {
		mlme_err(" peer_priv component object alloc failed");
		return QDF_STATUS_E_NOMEM;
	}

	status = wlan_objmgr_peer_component_obj_attach(peer,
						       WLAN_UMAC_COMP_MLME,
						       (void *)peer_priv,
						       QDF_STATUS_SUCCESS);

	if (QDF_IS_STATUS_ERROR(status)) {
		mlme_err("unable to attach peer_priv obj to peer obj");
		qdf_mem_free(peer_priv);
	}

	return status;
}

QDF_STATUS
mlme_peer_object_destroyed_notification(struct wlan_objmgr_peer *peer,
					void *arg)
{
	struct peer_mlme_priv_obj *peer_priv;
	QDF_STATUS status;

	if (!peer) {
		mlme_err(" peer is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	peer_priv = wlan_objmgr_peer_get_comp_private_obj(peer,
							  WLAN_UMAC_COMP_MLME);
	if (!peer_priv) {
		mlme_err(" peer MLME component object is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	status = wlan_objmgr_peer_component_obj_detach(peer,
						       WLAN_UMAC_COMP_MLME,
						       peer_priv);

	if (QDF_IS_STATUS_ERROR(status))
		mlme_err("unable to detach peer_priv obj to peer obj");

	qdf_mem_free(peer_priv);

	return status;
}
