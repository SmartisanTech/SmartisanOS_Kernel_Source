/*
 * Copyright (c) 2018 The Linux Foundation. All rights reserved.
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
 * DOC: declare UCFG APIs exposed by the mlme component
 */

#ifndef _WLAN_MLME_UCFG_API_H_
#define _WLAN_MLME_UCFG_API_H_

#include <wlan_objmgr_vdev_obj.h>
#include <wmi_unified_param.h>
#include <wlan_mlme_main.h>

/**
 * ucfg_mlme_init() - initialize mlme_ctx context.
 *
 * This function initializes the mlme context.
 *
 * Return: QDF_STATUS_SUCCESS - in case of success else return error
 */
QDF_STATUS ucfg_mlme_init(void);

/**
 * ucfg_mlme_deinit() - De initialize mlme_ctx context.
 *
 * This function De initializes mlme contex.
 *
 * Return: QDF_STATUS_SUCCESS - in case of success else return error
 */
QDF_STATUS ucfg_mlme_deinit(void);

/**
 * ucfg_mlme_get_ini_vdev_config() - get the ini capability of vdev
 * @vdev: pointer to the vdev obj
 *
 * This API will get the ini config of the vdev related to
 * the nss, chains params
 *
 * Return: pointer to the nss, chain param ini cfg structure
 */
static inline struct mlme_nss_chains *
ucfg_mlme_get_ini_vdev_config(struct wlan_objmgr_vdev *vdev)
{
	return mlme_get_ini_vdev_config(vdev);
}

/**
 * ucfg_mlme_get_dynamic_vdev_config() - get the dynamic capability of vdev
 * @vdev: pointer to the vdev obj
 *
 * This API will get the dynamic config of the vdev related to nss,
 * chains params
 *
 * Return: pointer to the nss, chain param dynamic cfg structure
 */
static inline struct mlme_nss_chains *
ucfg_mlme_get_dynamic_vdev_config(struct wlan_objmgr_vdev *vdev)
{
	return mlme_get_dynamic_vdev_config(vdev);
}

/**
 * ucfg_mlme_update_oce_flags: Update the OCE flags
 *
 * @pdev: pointer to pdev object
 * @cfg_value: INI value of oce feature flag
 *
 * Inline UCFG API to be used by HDD/OSIF callers to update the
 * OCE feature flags
 *
 * Return: void
 */
static inline
void ucfg_mlme_update_oce_flags(struct wlan_objmgr_pdev *pdev,
				uint8_t cfg_value)
{
	wlan_mlme_update_oce_flags(pdev, cfg_value);
}

#endif /* _WLAN_MLME_UCFG_API_H_ */
