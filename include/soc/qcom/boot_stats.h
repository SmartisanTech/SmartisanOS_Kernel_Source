/* Copyright (c) 2013-2014,2016 The Linux Foundation. All rights reserved.
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

#ifdef CONFIG_MSM_BOOT_STATS

#define TIMER_KHZ 32768
extern struct boot_stats __iomem *boot_stats;

struct boot_stats {
	uint32_t bootloader_start;
	uint32_t bootloader_end;
	uint32_t bootloader_display;
	uint32_t bootloader_load_kernel;
};

#define DDR_FREQ_EN_933MHZ_MASK 0x800
#define DDR_FREQ_EN_844MHZ_MASK 0x400
#define DDR_FREQ_EN_806MHZ_MASK 0x200
#define DDR_FREQ_EN_768MHZ_MASK 0x100
#define DDR_FREQ_EN_672MHZ_MASK 0x080
#define DDR_FREQ_EN_556MHZ_MASK 0x040
#define DDR_FREQ_EN_422MHZ_MASK 0x020
#define DDR_FREQ_EN_384MHZ_MASK 0x010
#define DDR_FREQ_EN_278MHZ_MASK 0x008
#define DDR_FREQ_EN_211MHZ_MASK 0x004
#define DDR_FREQ_EN_100MHZ_MASK 0x002
#define DDR_FREQ_EN_019MHZ_MASK 0x001

struct boot_shared_imem_cookie_type
{
  /* Magic number which indicates boot shared imem has been initialized
     and the content is valid.*/ 
  uint32_t shared_imem_magic;

  /* Number to indicate what version of this structure is being used */
  uint32_t shared_imem_version;
  
  /* Pointer that points to etb ram dump buffer, should only be set by HLOS */
  uint64_t etb_buf_addr;
  
  /* Region where HLOS will write the l2 cache dump buffer start address */
  uint64_t *l2_cache_dump_buff_ptr;

  /* When SBL which is A32 allocates the 64bit pointer above it will only
     consume 4 bytes.  When HLOS running in A64 mode access this it will over
     flow into the member below it.  Adding this padding will ensure 8 bytes
     are consumed so A32 and A64 have the same view of the remaining members. */
//  uint32_t a64_pointer_padding;

  /* Magic number for UEFI ram dump, if this cookie is set along with dload magic numbers,
     we don't enter dload mode but continue to boot. This cookie should only be set by UEFI*/
  uint32_t uefi_ram_dump_magic;
  
  uint32_t ddr_training_cookie;
  
  /* Abnormal reset cookie used by UEFI */
  uint32_t abnormal_reset_occurred;
  
  /* Reset Status Register */
  uint32_t reset_status_register;
  
  /* Boot Log Location Pointer to be accessed in UEFI */
  uint64_t boot_log_addr;
  
  /* Boot Log Size */
  uint32_t boot_log_size;
  
  /*Boot failure count */
  uint32_t boot_fail_count;
  
  /*Error code delivery through EDL */
  uint32_t sbl1_error_type;

    /* Please add new cookie here, do NOT modify or rearrange the existing cookies*/
  uint32_t offline_dump_flag;
  uint64_t kernel_log_buf_addr;
  uint32_t log_first_idx_addr;
  uint32_t log_next_idx_addr;
  uint64_t pon_reason;
  uint32_t is_enable_secure_boot;
  uint32_t offline_dump_happen;
  uint32_t limit_ddr;
  uint32_t offline_dump_mol;
  uint32_t ddr_freq_en_mask;
};

int boot_stats_init(void);
int boot_stats_exit(void);
unsigned long long int msm_timer_get_sclk_ticks(void);


uint64_t get_boot_reason(void);
uint32_t get_secure_boot_value(void);
#else
static inline int boot_stats_init(void) { return 0; }
unsigned long long int msm_timer_get_sclk_ticks(void) { return 0; }
#endif

#ifdef CONFIG_MSM_BOOT_TIME_MARKER

static inline int boot_marker_enabled(void) { return 1; }
void place_marker(const char *name);
#else
inline void place_marker(char *name);
static inline int boot_marker_enabled(void) { return 0; }
#endif
