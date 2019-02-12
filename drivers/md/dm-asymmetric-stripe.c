/*
 * Copyright (C) 2018 Smartisan, Inc.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * Author: <tgvlcw@gmail.com>
 * Name: Henry Liu
 *
 */


#include "dm.h"
#include <linux/device-mapper.h>
#include <linux/atomic.h>

#include <linux/module.h>
#include <linux/init.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/bitops.h>
#include <linux/slab.h>
#include <linux/log2.h>
#include <linux/workqueue.h>

#define DM_MSG_PREFIX "asm-striped"
#define DM_IO_ERROR_THRESHOLD 15

typedef struct asymmetric_stripe asm_stripe;
typedef struct asymmetric_stripe_c asm_stripe_c;
typedef struct asymmetric_stripe_node asm_stripe_node;

struct asymmetric_stripe_node {
	uint32_t stripe_id;
};

struct asymmetric_stripe {
	struct dm_dev *dev;

	/* The size of this target / num. stripes */
	sector_t physical_start;
	sector_t stripe_width;
	sector_t opt_io_size;
	sector_t internal_offs;
	uint32_t ratio;

	atomic_t error_count;
};

struct asymmetric_stripe_c {
	uint32_t stripes;

	uint32_t chunk_size;
	uint32_t total_ratio;
	sector_t avg_width;
	sector_t stripe_size;
	int stripe_size_shift;
	char ratio_str[128];

	/* Needed for handling events */
	struct dm_target *ti;

	/* Work struct used for triggering events*/
	struct work_struct trigger_event;

	uint32_t chunk_id;
	asm_stripe_node *node;
	asm_stripe stripe[0];
};

/*
 * An event is triggered whenever a drive
 * drops out of a stripe volume.
 */
static void trigger_event(struct work_struct *work)
{
	asm_stripe_c *sc = container_of(work, asm_stripe_c, trigger_event);

	dm_table_event(sc->ti->table);
}

static inline asm_stripe_c *alloc_context(unsigned int stripes)
{
	size_t len;

	if (dm_array_too_big(sizeof(asm_stripe_c),
				sizeof(asm_stripe),
				stripes))
		return NULL;

	len = sizeof(asm_stripe_c) + (sizeof(asm_stripe) * stripes);

	return kmalloc(len, GFP_KERNEL);
}

/*
 * Parse a single <dev> <sector> pair
 */
static int get_stripe(struct dm_target *ti,
		asm_stripe_c *sc,
		unsigned int stripe,
		char **argv)
{
	unsigned long long start;
	char dummy;
	int ret;
	unsigned int id = stripe;
	sector_t offs_prev, size;
	uint32_t i;
	uint32_t *chunk_id = &sc->chunk_id;

	if (sscanf(argv[1], "%llu%c", &start, &dummy) != 1)
		return -EINVAL;

	ret = dm_get_device(ti, argv[0], dm_table_get_mode(ti->table),
			&sc->stripe[stripe].dev);
	if (ret)
		return ret;

	sc->stripe[id].physical_start = start;
	sc->stripe[id].stripe_width = sc->avg_width * sc->stripe[id].ratio;
	sc->stripe[id].opt_io_size = sc->chunk_size * sc->stripe[id].ratio;

	if (id > 0) {
		offs_prev = sc->stripe[id-1].internal_offs;
		size = offs_prev + sc->stripe[id-1].opt_io_size;
	} else
		size = 0;

	sc->stripe[id].internal_offs = size;

	for (i = 0; i < sc->stripe[id].ratio; i++, (*chunk_id)++)
		sc->node[*chunk_id].stripe_id = id;

	return 0;
}

static int set_stripe_ratio(struct dm_target *ti,
		asm_stripe_c *sc,
		char *ratio_str)
{
	char *p;
	unsigned int i;
	uint32_t r = 0, ratio;
	char *tmp_ratio = ratio_str;
	size_t len;

	if (sizeof(sc->ratio_str) < strlen(ratio_str)) {
		ti->error = "Too big stripe ratio string";
		return -ENOMEM;
	}

	strlcpy(sc->ratio_str, ratio_str, strlen(ratio_str) + 1);
	for (i = 0; i < sc->stripes; i++) {
		p  = strsep(&tmp_ratio, ":");
		if (p == NULL)
			return -EINVAL;

		if (kstrtouint(p, 10, &ratio) || !ratio)
			return -EINVAL;

		sc->stripe[i].ratio = ratio;
		r += ratio;
	}

	len = sizeof(asm_stripe_node) * r;
	sc->node = kmalloc(len, GFP_KERNEL);
	if (sc->node == NULL) {
		ti->error = "Memory allocation for striped node failed";
		return -ENOMEM;
	}

	sc->total_ratio = r;
	sc->avg_width = ti->len / r;
	sc->stripe_size = r * sc->chunk_size;

	return 0;
}

/*
 * Construct a striped mapping.
 * <number of stripes> <chunk size> <ratio> [<dev_path> <offset>]+
 */
static int asymmetric_stripe_ctr(struct dm_target *ti,
		unsigned int argc,
		char **argv)
{
	asm_stripe_c *sc;
	sector_t width;
	uint32_t stripes;
	uint32_t chunk_size;
	int r;
	unsigned int i;

	if (argc < 2) {
		ti->error = "Not enough arguments";
		return -EINVAL;
	}

	if (kstrtouint(argv[0], 10, &stripes) || !stripes) {
		ti->error = "Invalid stripe count";
		return -EINVAL;
	}

	if (kstrtouint(argv[1], 10, &chunk_size) || !chunk_size) {
		ti->error = "Invalid chunk_size";
		return -EINVAL;
	}

	/*
	 * Do we have enough arguments for that many stripes ?
	 */
	if (argc != (3 + 2 * stripes)) {
		ti->error = "Not enough destinations specified";
		return -EINVAL;
	}

	sc = alloc_context(stripes);
	if (!sc) {
		ti->error = "Memory allocation for striped context failed";
		return -ENOMEM;
	}

	INIT_WORK(&sc->trigger_event, trigger_event);

	/* Set pointer to dm target; used in trigger_event */
	sc->ti = ti;
	sc->stripes = stripes;

	ti->asymmetric_chunk_supported = true;
	ti->num_flush_bios = stripes;
	ti->num_discard_bios = stripes;
	ti->num_write_same_bios = stripes;
	sc->chunk_size = chunk_size;
	sc->chunk_id = 0;

	if (set_stripe_ratio(ti, sc, argv[2]) < 0)
		return -EINVAL;

	if (sc->stripe_size & (sc->stripe_size - 1))
		sc->stripe_size_shift = -1;
	else
		sc->stripe_size_shift = __ffs(sc->stripe_size);

	width = ti->len;
	if (sector_div(width, sc->total_ratio * chunk_size)) {
		ti->error = "Target length not divisible by number of stripes";
		return -EINVAL;
	}

	argv++;
	/*
	 * Get the stripe destinations.
	 */
	for (i = 0; i < stripes; i++) {
		argv += 2;

		r = get_stripe(ti, sc, i, argv);
		if (r < 0) {
			ti->error = "Couldn't parse stripe destination";
			goto parse_error;
		}
		atomic_set(&(sc->stripe[i].error_count), 0);
	}

	ti->private = sc;

	return 0;

parse_error:
	while (i--)
		dm_put_device(ti, sc->stripe[i].dev);
	kfree(sc->node);
	kfree(sc);
	return -EINVAL;
}

static inline sector_t stripe_index_fetch(asm_stripe_c *sc,
		sector_t *sector,
		uint32_t *stripe)
{
	sector_t width_offset;
	uint32_t chunk_id;
	
	*sector = dm_target_offset(sc->ti, *sector);

	if (sc->stripe_size_shift < 0)
		width_offset = sector_div(*sector, sc->stripe_size);
	else {
		width_offset = *sector & (sc->stripe_size - 1);
		*sector >>= sc->stripe_size_shift;
	}

	chunk_id = width_offset / sc->chunk_size;
	*stripe = sc->node[chunk_id].stripe_id;
	width_offset -= sc->stripe[*stripe].internal_offs;

	return width_offset;
}

static void asymmetric_stripe_dtr(struct dm_target *ti)
{
	unsigned int i;
	asm_stripe_c *sc = (asm_stripe_c *)ti->private;

	for (i = 0; i < sc->stripes; i++)
		dm_put_device(ti, sc->stripe[i].dev);

	flush_work(&sc->trigger_event);
	kfree(sc->node);
	kfree(sc);
}

static void asymmetric_stripe_map_sector(asm_stripe_c *sc,
		sector_t sector,
		uint32_t *stripe,
		sector_t *result)
{
	sector_t width_offset;

	width_offset = stripe_index_fetch(sc, &sector, stripe);

	*result = sector * sc->stripe[*stripe].opt_io_size + width_offset;
}

static void asymmetric_stripe_map_range_sector(asm_stripe_c *sc,
		sector_t sector,
		uint32_t target_stripe,
		sector_t *result)
{
	sector_t width_offset;
	uint32_t stripe;

	width_offset = stripe_index_fetch(sc, &sector, &stripe);

	*result = sector * sc->stripe[target_stripe].opt_io_size;

	if (target_stripe < stripe)
		*result += sc->stripe[target_stripe].opt_io_size;
	else if (target_stripe == stripe)
		*result += width_offset;
}

static int asymmetric_stripe_map_range(asm_stripe_c *sc,
		struct bio *bio,
		uint32_t target_stripe)
{
	sector_t begin, end;

	asymmetric_stripe_map_range_sector(sc, bio->bi_iter.bi_sector,
			target_stripe, &begin);
	asymmetric_stripe_map_range_sector(sc, bio_end_sector(bio),
			target_stripe, &end);
	if (begin < end) {
		bio->bi_bdev = sc->stripe[target_stripe].dev->bdev;
		bio->bi_iter.bi_sector = begin +
			sc->stripe[target_stripe].physical_start;
		bio->bi_iter.bi_size = to_bytes(end - begin);
		return DM_MAPIO_REMAPPED;
	}

	/* The range doesn't map to the target stripe */
	bio_endio(bio);

	return DM_MAPIO_SUBMITTED;
}

static int asymmetric_stripe_map(struct dm_target *ti, struct bio *bio)
{
	asm_stripe_c *sc = ti->private;
	uint32_t stripe;
	unsigned target_bio_nr;

	if (bio->bi_opf & REQ_PREFLUSH) {
		target_bio_nr = dm_bio_get_target_bio_nr(bio);
		BUG_ON(target_bio_nr >= sc->stripes);
		bio->bi_bdev = sc->stripe[target_bio_nr].dev->bdev;
		return DM_MAPIO_REMAPPED;
	}
	if (unlikely(bio_op(bio) == REQ_OP_DISCARD) ||
	    unlikely(bio_op(bio) == REQ_OP_WRITE_SAME)) {
		target_bio_nr = dm_bio_get_target_bio_nr(bio);
		BUG_ON(target_bio_nr >= sc->stripes);
		return asymmetric_stripe_map_range(sc, bio, target_bio_nr);
	}

	asymmetric_stripe_map_sector(sc, bio->bi_iter.bi_sector,
			&stripe, &bio->bi_iter.bi_sector);

	bio->bi_iter.bi_sector += sc->stripe[stripe].physical_start;
	bio->bi_bdev = sc->stripe[stripe].dev->bdev;

	return DM_MAPIO_REMAPPED;
}

static long asymmetric_stripe_direct_access(struct dm_target *ti, sector_t sector,
				 void **kaddr, pfn_t *pfn, long size)
{
	asm_stripe_c *sc = ti->private;
	uint32_t stripe;
	struct block_device *bdev;
	struct blk_dax_ctl dax = {
		.size = size,
	};
	long ret;

	asymmetric_stripe_map_sector(sc, sector, &stripe, &dax.sector);

	dax.sector += sc->stripe[stripe].physical_start;
	bdev = sc->stripe[stripe].dev->bdev;

	ret = bdev_direct_access(bdev, &dax);
	*kaddr = dax.addr;
	*pfn = dax.pfn;

	return ret;
}

/*
 * Stripe status:
 *
 * INFO
 * #stripes [stripe_name <stripe_name>] [group word count]
 * [error count 'A|D' <error count 'A|D'>]
 *
 * TABLE
 * #stripes [stripe chunk size] [ratio]
 * [stripe_name physical_start <stripe_name physical_start>]
 *
 */

static void asymmetric_stripe_status(struct dm_target *ti,
		status_type_t type,
		unsigned status_flags,
		char *result,
		unsigned maxlen)
{
	asm_stripe_c *sc = (asm_stripe_c *) ti->private;
	char buffer[sc->stripes + 1];
	unsigned int sz = 0;
	unsigned int i;

	switch (type) {
	case STATUSTYPE_INFO:
		DMEMIT("%d ", sc->stripes);
		for (i = 0; i < sc->stripes; i++)  {
			DMEMIT("%s ", sc->stripe[i].dev->name);
			buffer[i] = atomic_read(&(sc->stripe[i].error_count))
				    ? 'D' : 'A';
		}
		buffer[i] = '\0';
		DMEMIT("1 %s", buffer);
		break;

	case STATUSTYPE_TABLE:
		DMEMIT("%u %u %s", sc->stripes,
			sc->chunk_size, sc->ratio_str);
		for (i = 0; i < sc->stripes; i++)
			DMEMIT(" %s %lu", sc->stripe[i].dev->name,
				sc->stripe[i].physical_start);
		break;
	}
}

static int asymmetric_stripe_end_io(struct dm_target *ti,
		struct bio *bio,
		int error)
{
	unsigned i;
	char major_minor[16];
	asm_stripe_c *sc = ti->private;

	if (!error)
		return 0; /* I/O complete */

	if ((error == -EWOULDBLOCK) && (bio->bi_opf & REQ_RAHEAD))
		return error;

	if (error == -EOPNOTSUPP)
		return error;

	memset(major_minor, 0, sizeof(major_minor));
	snprintf(major_minor, sizeof(major_minor), "%d:%d",
			MAJOR(disk_devt(bio->bi_bdev->bd_disk)),
			MINOR(disk_devt(bio->bi_bdev->bd_disk)));

	/*
	 * Test to see which stripe drive triggered the event
	 * and increment error count for all stripes on that device.
	 * If the error count for a given device exceeds the threshold
	 * value we will no longer trigger any further events.
	 */
	for (i = 0; i < sc->stripes; i++)
		if (!strcmp(sc->stripe[i].dev->name, major_minor)) {
			atomic_inc(&(sc->stripe[i].error_count));
			if (atomic_read(&(sc->stripe[i].error_count)) <
					DM_IO_ERROR_THRESHOLD)
				schedule_work(&sc->trigger_event);
		}

	return error;
}

static int asymmetric_stripe_iterate_devices(struct dm_target *ti,
		iterate_devices_callout_fn fn,
		void *data)
{
	asm_stripe_c *sc = ti->private;
	int ret = 0;
	unsigned i = 0;

	do {
		ret = fn(ti, sc->stripe[i].dev,
				sc->stripe[i].physical_start,
				sc->stripe[i].stripe_width, data);
	} while (!ret && ++i < sc->stripes);

	return ret;
}

static void asymmetric_stripe_io_hints(struct dm_target *ti,
		struct queue_limits *limits)
{
	asm_stripe_c *sc = ti->private;
	unsigned chunk_size = sc->chunk_size << SECTOR_SHIFT;

	blk_limits_io_min(limits, chunk_size);
	blk_limits_io_opt(limits, chunk_size * sc->total_ratio);
}

static void asymmetric_stripe_io_len_calculate(struct dm_target *ti,
		sector_t offset,
		sector_t *optimal_len)
{
	asm_stripe_c *sc = ti->private;
	sector_t width_offset;
	uint32_t stripe;

	width_offset = stripe_index_fetch(sc, &offset, &stripe);
	*optimal_len = sc->stripe[stripe].opt_io_size - width_offset;
}

static struct target_type asymmetric_stripe_target = {
	.name	= "asm-striped",
	.version = {1, 0, 0},
	.module = THIS_MODULE,
	.ctr	= asymmetric_stripe_ctr,
	.dtr	= asymmetric_stripe_dtr,
	.map	= asymmetric_stripe_map,
	.end_io = asymmetric_stripe_end_io,
	.status = asymmetric_stripe_status,
	.iterate_devices = asymmetric_stripe_iterate_devices,
	.io_hints = asymmetric_stripe_io_hints,
	.io_calculate = asymmetric_stripe_io_len_calculate,
	.direct_access = asymmetric_stripe_direct_access,
};

static int __init dm_stripe_asymmetric_init(void)
{
	int r;

	r = dm_register_target(&asymmetric_stripe_target);
	if (r < 0)
		DMWARN("target registration failed");

	return r;
}

static void __exit dm_stripe_asymmetric_exit(void)
{
	dm_unregister_target(&asymmetric_stripe_target);
}

module_init(dm_stripe_asymmetric_init);
module_exit(dm_stripe_asymmetric_exit);

MODULE_AUTHOR("Henry <liuchaowei@smartisan.com>");
MODULE_LICENSE("GPL");
