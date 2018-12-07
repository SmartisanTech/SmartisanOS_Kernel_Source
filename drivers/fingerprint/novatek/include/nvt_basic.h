/**
    Novatek's basic macro.

    Novatek's basic macro for fingerprint solution.

    @file       nvt_basic.h
    @ingroup
    @note       Nothing.

    Copyright   Novatek Microelectronics Corp. 2015.  All rights reserved.
*/

#ifndef _NVT_BASIC_H
#define _NVT_BASIC_H

/**
    @addtogroup
*/
//@{

/**
    Macro to generate dummy element for enum type to expand enum size to 4 bytes
*/
//@{
#define ENUM_DUMMY(name)    E_##name = 0x10000000
//@}

/**
    @name Align macros

    Align floor, align round, and align ceil

    @note base must be 2^n, where n = 1, 2, 3, ...
*/
//@{
#define ALIGN_FLOOR(value, base)    ((value) & ~((base)-1))                     ///< Align Floor
#define ALIGN_ROUND(value, base)    ALIGN_FLOOR((value) + ((base)/2), base)     ///< Align Round
#define ALIGN_CEIL(value, base)     ALIGN_FLOOR((value) + ((base)-1), base)     ///< Align Ceil
//@}

/**
    @name Align (round off)

    Round Off to 32, 16, 8 and 4

    @note Example: ALIGN_ROUND_32(32) = 32, ALIGN_ROUND_32(47) = 32, ALIGN_ROUND_32(48) = 64
*/
//@{
#define ALIGN_ROUND_32(a)       ALIGN_ROUND(a, 32)  ///< Round Off to 32
#define ALIGN_ROUND_16(a)       ALIGN_ROUND(a, 16)  ///< Round Off to 16
#define ALIGN_ROUND_8(a)        ALIGN_ROUND(a, 8)   ///< Round Off to 8
#define ALIGN_ROUND_4(a)        ALIGN_ROUND(a, 4)   ///< Round Off to 4
//@}

/**
    @name Align (round up)

    Round Up to 32, 16, 8 and 4.

    @note Example: ALIGN_CEIL_32(32) = 32, ALIGN_CEIL_32(33) = 64, ALIGN_CEIL_32(63) = 64
*/
//@{
#define ALIGN_CEIL_32(a)        ALIGN_CEIL(a, 32)   ///< Round Up to 32
#define ALIGN_CEIL_16(a)        ALIGN_CEIL(a, 16)   ///< Round Up to 16
#define ALIGN_CEIL_8(a)         ALIGN_CEIL(a, 8)    ///< Round Up to 8
#define ALIGN_CEIL_4(a)         ALIGN_CEIL(a, 4)    ///< Round Up to 4
//@}

/**
    @name Align (round down)

    Round Down to 32, 16, 8 and 4.

    @note Example: ALIGN_FLOOR_32(32) = 32, ALIGN_FLOOR_32(33) = 32, ALIGN_FLOOR_32(63) = 32
*/
//@{
#define ALIGN_FLOOR_32(a)       ALIGN_FLOOR(a, 32)  ///< Round down to 32
#define ALIGN_FLOOR_16(a)       ALIGN_FLOOR(a, 16)  ///< Round down to 16
#define ALIGN_FLOOR_8(a)        ALIGN_FLOOR(a, 8)   ///< Round down to 8
#define ALIGN_FLOOR_4(a)        ALIGN_FLOOR(a, 4)   ///< Round down to 4
//@}

// Memory alignment base, it's platform dependent
#define ALIGN_BASE              (sizeof(void *))

/**
    @name Absolute Value

    Absolute value of real number.

    @note Example: NVT_ABS(1) = 1, NVT_ABS(-1) = 1.
*/
//@{
#define NVT_ABS(a)              ((a) > 0 ? a : -(a))
//@}

#if defined(_WIN32)
// Windows

#define __EXPORT_SYMBOL__(...)
#define __PACKED__(...)                 __pragma(pack(push, 1)) __VA_ARGS__ __pragma(pack(pop))

#elif defined(__KERNEL__)
// Linux Kernel

#define __EXPORT_SYMBOL__(...)          EXPORT_SYMBOL(__VA_ARGS__)
#define __PACKED__(...)                 __VA_ARGS__ __attribute__((packed))

#elif defined(__FPR_ENG_USERSPACE__)
// Linux User space

#define __EXPORT_SYMBOL__(...)
#define __PACKED__(...)                 __VA_ARGS__ __attribute__((packed))

#else

/*
// TEE ... (TBD)

*/

#error Unknown platform

#endif

//@}

#endif // _NVT_BASIC_H
