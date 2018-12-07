/*
 * Copyright (c) 2013-2015, The Linux Foundation. All rights reserved.
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
#define TRACE_SYSTEM fsdbg

#if !defined(_TRACE_FSDBG_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_FSDBG_H

#include <linux/tracepoint.h>

DECLARE_EVENT_CLASS(fsdbg_fullname_template,
	TP_PROTO(char* rw_str, unsigned long i_ino, char* fullname, size_t count, loff_t offset, int duration),

	TP_ARGS(rw_str, i_ino, fullname, count, offset, duration),

	TP_STRUCT__entry(
		__string(rw_str, rw_str)
		__field(unsigned long, i_ino)
		__string(fullname, fullname)
		__field(size_t, count)
		__field(loff_t, offset)
		__field(int, duration)
	),

	TP_fast_assign(
		__assign_str(rw_str, rw_str);
		__entry->i_ino = i_ino;
		__assign_str(fullname, fullname);
		__entry->count = count;
		__entry->offset = offset;
		__entry->duration = duration;
	),

	TP_printk("%s, inode: %lu, name: %s, len: %lu, pos: %lld, duration: %d\n",
		__get_str(rw_str), __entry->i_ino, __get_str(fullname), __entry->count, __entry->offset, __entry->duration)

);


DEFINE_EVENT(fsdbg_fullname_template, fsdbg_ext4_rw,
	TP_PROTO(char* rw_str, unsigned long i_ino, char* fullname, size_t count, loff_t offset, int duration),
	TP_ARGS(rw_str, i_ino, fullname, count, offset, duration));

DEFINE_EVENT(fsdbg_fullname_template, fsdbg_f2fs_rw,
	TP_PROTO(char* rw_str, unsigned long i_ino, char* fullname, size_t count, loff_t offset, int duration),
	TP_ARGS(rw_str, i_ino, fullname, count, offset, duration));

DEFINE_EVENT(fsdbg_fullname_template, fsdbg_vfs_rw,
	TP_PROTO(char* rw_str, unsigned long i_ino, char* fullname, size_t count, loff_t offset, int duration),
	TP_ARGS(rw_str, i_ino, fullname, count, offset, duration));

TRACE_EVENT(fsdbg_blk_rw,
	TP_PROTO(char* rw_str, unsigned long i_ino, char* fullname, unsigned int count, u64 offset, const char* dev_name),

	TP_ARGS(rw_str, i_ino, fullname, count, offset, dev_name),

	TP_STRUCT__entry(
		__string(rw_str, rw_str)
		__field(unsigned long, i_ino)
		__string(fullname, fullname)
		__field(unsigned int, count)
		__field(u64, offset)
		__string(dev_name, dev_name)
	),

	TP_fast_assign(
		__assign_str(rw_str, rw_str);
		__entry->i_ino = i_ino;
		__assign_str(fullname, fullname);
		__entry->count = count;
		__entry->offset = offset;
		__assign_str(dev_name, dev_name);
	),

	TP_printk("%s block %Lu on %s (%u sectors) (inode:%lu, name:%s)\n",
		__get_str(rw_str), __entry->offset, __get_str(dev_name), __entry->count, __entry->i_ino, __get_str(fullname))

);

TRACE_EVENT(fsdbg_print,
	TP_PROTO(char* str),

	TP_ARGS(str),

	TP_STRUCT__entry(
		__string(str, str)
	),

	TP_fast_assign(
		__assign_str(str, str);
	),

	TP_printk("%s",__get_str(str))
);


#endif /* if !defined(_TRACE_FSDBG_H) || defined(TRACE_HEADER_MULTI_READ) */

/* This part must be outside protection */
#include <trace/define_trace.h>
