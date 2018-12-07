/*
** =============================================================================
** Copyright (c) 2017  IMAGIS co.,
**
** This program is free software; you can redistribute it and/or
** modify it under the terms of the GNU General Public License
** as published by the Free Software Foundation; either version 2
** of the License, or (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** File:
**     isa1200.c
**
** Description:
**     ISA1200 Haptic driver
**
** =============================================================================
*/
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/hrtimer.h>
#include <linux/mutex.h>
#include <linux/version.h>

#include "isa1200.h"

volatile int gPheIdx = 0;
stPhe_t *gpPhe;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0)
/* ver 4.9.65 */
#define KTHREAD_INIT_WORKER     kthread_init_worker
#define KTHREAD_INIT_WORK       kthread_init_work
#define KTHREAD_QUEUE_WORK      kthread_queue_work
#define KTHREAD_FLUSH_WORKER    kthread_flush_worker
#define KTHREAD_FLUSH_WORK      kthread_flush_work
#else
/* ver 4.4.88 */
#define KTHREAD_INIT_WORKER     init_kthread_worker
#define KTHREAD_INIT_WORK       init_kthread_work
#define KTHREAD_QUEUE_WORK      queue_kthread_work
#define KTHREAD_FLUSH_WORKER    flush_kthread_worker
#define KTHREAD_FLUSH_WORK      flush_kthread_work
#endif

ktime_t gktime;

extern stPhe_t gstPheStop;
extern stPheInfo_t gstPheInfoStop;

static void isa1200_player_work_func(struct kthread_work *work)
{
    stIsa1200Data_t *pIsa1200 = container_of(work, stIsa1200Data_t, kwork);

    mutex_lock(&pIsa1200->lock);

    isa1200_set_amplitude(pIsa1200, gpPhe->amp);
    //gpPhe++;

    mutex_unlock(&pIsa1200->lock);

    //pr_info("[HPT] : %d\n", gpPhe->amp);
}

static enum hrtimer_restart player_stop_tick_func(struct hrtimer *ptimer)
{
    stIsa1200Data_t *pIsa1200 = container_of(ptimer, stIsa1200Data_t, timer_stop);

    gpPhe = &gstPheStop;

    KTHREAD_QUEUE_WORK(&pIsa1200->kworker, &pIsa1200->kwork);
    pIsa1200->bPlayingHaptic = false;

    return HRTIMER_NORESTART;
}

static enum hrtimer_restart player_tick_func(struct hrtimer *ptimer)
{
    ktime_t ktime;

    stPheInfo_t *pinfo;
    stPhe_t *pphe;

    stIsa1200Data_t *pIsa1200 = container_of(ptimer, stIsa1200Data_t, timer);

#if 0 // debug
    ktime = ktime_sub(ptimer->base->get_time(), gktime);
    gktime = ptimer->base->get_time();

    pr_info("[HPT] %d :\n", (int32_t)ktime_to_ms(ktime));
#endif

    pinfo = pIsa1200->pPheInfo;
    pphe = pIsa1200->pPhe;

    if ((gPheIdx+1) >= pinfo->count) {
        pr_info("[HPT] player end\n");
	gpPhe = &gstPheStop;

	KTHREAD_QUEUE_WORK(&pIsa1200->kworker, &pIsa1200->kwork);
        pIsa1200->bPlayingHaptic = false;

        return HRTIMER_NORESTART;
    }

    gpPhe = &pphe[gPheIdx];

    KTHREAD_QUEUE_WORK(&pIsa1200->kworker, &pIsa1200->kwork);

    ktime = ms_to_ktime(pphe[gPheIdx+1].ms - pphe[gPheIdx].ms);
    hrtimer_forward_now(&pIsa1200->timer, ktime);


    //pr_info("[HPT] %3d: %5d\n", gPheIdx, pphe[gPheIdx+1].ms - pphe[gPheIdx].ms);

    gPheIdx++;

    return HRTIMER_RESTART;
}


bool isa1200_player_stop(stIsa1200Data_t *pIsa1200)
{
    int ret = 0;

    hrtimer_cancel(&pIsa1200->timer);

    gpPhe = &gstPheStop;

    KTHREAD_QUEUE_WORK(&pIsa1200->kworker, &pIsa1200->kwork);
    pIsa1200->bPlayingHaptic = false;

    return ret;
}

int isa1200_se_player_start(stIsa1200Data_t *pIsa1200)
{
    int ret;
    uint32_t play_ms = 0;

    ktime_t  ktime;

    stSimpleEfft_t *pse = &pIsa1200->stSE;

    isa1200_haptic_reset(pIsa1200);

    ret = isa1200_set_se(pIsa1200, pse);
    if (ret < 0) {
        pr_err("[HPT] Err, %s(), set se failed(%d)\n", __func__, ret);
        return ret;
    }

    play_ms = (pse->fwd + pse->rvs) * 1000 / pse->freq;

    ktime = ms_to_ktime(play_ms + 1);
    hrtimer_start(&pIsa1200->timer_stop, ktime, HRTIMER_MODE_REL);

    gktime = ktime;

    return 0;
}

int isa1200_phe_player_start(stIsa1200Data_t *pIsa1200)
{
    int ret = 0;

    ktime_t  ktime;

    stPheInfo_t *pinfo = pIsa1200->pPheInfo;
    stPhe_t *pphe = pIsa1200->pPhe;

    ret = isa1200_set_amplitude(pIsa1200, pphe->amp);
    if (ret < 0) {
        pr_err("[HPT] Err, %s(), set amplitude(%d)\n", __func__, pphe->amp);
        return ret;
    }

    if (pinfo->count < 2)
        return 0;

    gPheIdx = 1;

    ktime = ms_to_ktime(pphe[gPheIdx].ms);
    //pr_info("[HPT] %3d: %5d\n", gPheIdx-1, pphe[gPheIdx].ms);
    hrtimer_start(&pIsa1200->timer, ktime, HRTIMER_MODE_REL);

    gktime = ktime;

    gpPhe = &pphe[gPheIdx];

    return 0;
}

bool isa1200_player_start(stIsa1200Data_t *pIsa1200)
{
    int ret;
    uint32_t play_ms;

    stPheInfo_t *pinfo;
    stPhe_t *pphe_end;

    pinfo = pIsa1200->pPheInfo;

    hrtimer_cancel(&pIsa1200->timer);

    //isa1200_haptic_reset(pIsa1200);

    ret = isa1200_set_frequency(pIsa1200, pinfo->freq);
    if (ret < 0) {
        pr_err("[HPT] Err, %s() set freq failed(%d)!!\n", __func__, ret);
        goto end_player_start;
    }

    pIsa1200->bPlayingHaptic = true;

    pphe_end = &pIsa1200->pPhe[pinfo->count - 1];
    play_ms = pphe_end->ms;

    if (pIsa1200->bPheMode == false) {
        ret = isa1200_se_player_start(pIsa1200);
        if (ret < 0)
            goto end_player_start;
    }
    else {
        ret = isa1200_phe_player_start(pIsa1200);
        if (ret < 0)
            goto end_player_start;
    }

    pr_info("[HPT] player time: %d\n", play_ms);

    return true;

end_player_start:
    pIsa1200->pPheInfo = NULL;
    pIsa1200->bPlayingHaptic = false;

    return false;
}



void isa1200_player_timer_init(stIsa1200Data_t *pIsa1200)
{
    struct task_struct *ptask;

    /* timer initialize */
    hrtimer_init(&pIsa1200->timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
    pIsa1200->timer.function = player_tick_func;

    hrtimer_init(&pIsa1200->timer_stop, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
    pIsa1200->timer_stop.function = player_stop_tick_func;

    /* kthread work initialize */
    KTHREAD_INIT_WORKER(&pIsa1200->kworker);
    ptask = kthread_run(kthread_worker_fn, &pIsa1200->kworker, "isa1200_player");
    if (IS_ERR(ptask))
        pr_err("[HPT] Failed to create task\n");
    KTHREAD_INIT_WORK(&pIsa1200->kwork, isa1200_player_work_func);
}

void isa1200_player_timer_cancel(stIsa1200Data_t *pIsa1200)
{
    KTHREAD_FLUSH_WORK(&pIsa1200->kwork);

    hrtimer_cancel(&pIsa1200->timer);
}
