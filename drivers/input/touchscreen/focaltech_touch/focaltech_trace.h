/* Copyright (c) 2015, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM focaltech
#define TRACE_INCLUDE_FILE focaltech_trace

#if !defined(_FOCALTECH_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _FOCALTECH_TRACE_H

#include <linux/tracepoint.h>
#include "focaltech_core.h"

TRACE_EVENT(
	fts_ts_suspend,

	TP_PROTO(int num),

	TP_ARGS(num),

	TP_STRUCT__entry(
		__field(int,	num)
	),

	TP_fast_assign(
		__entry->num = num;
	),

	TP_printk("flag =%d\n", __entry->num)
);

TRACE_EVENT(
	fts_ts_resume,

	TP_PROTO(int num),

	TP_ARGS(num),

	TP_STRUCT__entry(
		__field(int,	num)
	),

	TP_fast_assign(
		__entry->num = num;
	),

	TP_printk("flag =%d\n", __entry->num)
);

TRACE_EVENT(
	fts_read_touchdata,

	TP_PROTO(int num),

	TP_ARGS(num),

	TP_STRUCT__entry(
		__field(int,	num)
	),

	TP_fast_assign(
		__entry->num = num;
	),

	TP_printk("num =%d\n", __entry->num)
);

TRACE_EVENT(
	fts_report_value,

	TP_PROTO(int id, int pos_x, int pos_y),

	TP_ARGS(id, pos_x, pos_y),

	TP_STRUCT__entry(
		__field(int,	id)
		__field(int,	pos_x)
		__field(int,	pos_y)
	),

	TP_fast_assign(
		__entry->id = id;
		__entry->pos_x = pos_x;
		__entry->pos_y = pos_y;
	),

	TP_printk("id =%d pos_x = %d pos_y = %d\n", __entry->id, __entry->pos_x, __entry->pos_y)
);

#endif /* _FOCALTECH_TRACE_H */

/* This part must be outside protection */
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#include <trace/define_trace.h>
