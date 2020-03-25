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
 * DOC: define UCFG APIs exposed by the mlme component
 */

#include <wlan_mlme_ucfg_api.h>
#include <wlan_objmgr_global_obj.h>
#include <wlan_cmn.h>
#include <wlan_mlme_main.h>

QDF_STATUS ucfg_mlme_init(void)
{
	QDF_STATUS status;

	status = wlan_objmgr_register_vdev_create_handler(
			WLAN_UMAC_COMP_MLME,
			mlme_vdev_object_created_notification,
			NULL);
	if (QDF_IS_STATUS_ERROR(status)) {
		mlme_err("vdev create register notification failed");
		return QDF_STATUS_E_FAILURE;
	}

	status = wlan_objmgr_register_vdev_destroy_handler(
			WLAN_UMAC_COMP_MLME,
			mlme_vdev_object_destroyed_notification,
			NULL);
	if (QDF_IS_STATUS_ERROR(status)) {
		mlme_err("vdev destroy register notification failed");
		return QDF_STATUS_E_FAILURE;
	}

	status = wlan_objmgr_register_peer_create_handler(
			WLAN_UMAC_COMP_MLME,
			mlme_peer_object_created_notification,
			NULL);
	if (QDF_IS_STATUS_ERROR(status)) {
		mlme_err("peer create register notification failed");
		return QDF_STATUS_E_FAILURE;
	}

	status = wlan_objmgr_register_peer_destroy_handler(
			WLAN_UMAC_COMP_MLME,
			mlme_peer_object_destroyed_notification,
			NULL);
	if (QDF_IS_STATUS_ERROR(status)) {
		mlme_err("peer destroy register notification failed");
		return QDF_STATUS_E_FAILURE;
	}

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS ucfg_mlme_deinit(void)
{
	QDF_STATUS status;

	status = wlan_objmgr_unregister_peer_destroy_handler(
			WLAN_UMAC_COMP_MLME,
			mlme_peer_object_destroyed_notification,
			NULL);

	status = wlan_objmgr_unregister_peer_create_handler(
			WLAN_UMAC_COMP_MLME,
			mlme_peer_object_created_notification,
			NULL);

	status = wlan_objmgr_unregister_vdev_destroy_handler(
			WLAN_UMAC_COMP_MLME,
			mlme_vdev_object_destroyed_notification,
			NULL);

	status = wlan_objmgr_unregister_vdev_create_handler(
			WLAN_UMAC_COMP_MLME,
			mlme_vdev_object_created_notification,
			NULL);

	return status;
}
