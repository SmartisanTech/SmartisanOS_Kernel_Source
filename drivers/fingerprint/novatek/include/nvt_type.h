/**
    Available data type declaration.

    Declare all the data type for Novatek's Fingerprint solution.
    Also inlcude some basic macro.

    @file       nvt_type.h
    @ingroup
    @note       Nothing.

    Copyright   Novatek Microelectronics Corp. 2015.  All rights reserved.
*/

#include "nvt_basic.h"

#ifndef _NVT_TYPE_H
#define _NVT_TYPE_H

/**
    @addtogroup
*/
//@{

//
// Datatype     LP64    ILP64   LLP64   ILP32   LP32
//
// char         8       8       8       8       8
// short        16      16      16      16      16
// int          32      64      32      32      16
// long         64      64      32      32      32
// long long    64      64      64      64      64
// pointer      64      64      64      32      32
//
/**
    @name       Novatek's integer type
*/
//@{
#ifdef CONFIG_ARM64

//For Linux LP64 system, can also fit windows LLP64 system.
typedef unsigned long long  NVT_UINT64;     ///< Unsigned 64 bits data type
typedef signed long long    NVT_INT64;      ///< Signed 64 bits data type
typedef unsigned int        NVT_UINT32;     ///< Unsigned 32 bits data type
typedef signed int          NVT_INT32;      ///< Signed 32 bits data type
typedef unsigned short      NVT_UINT16;     ///< Unsigned 16 bits data type
typedef signed short        NVT_INT16;      ///< Signed 16 bits data type
typedef unsigned char       NVT_UINT8;      ///< Unsigned 8 bits data type
typedef signed char         NVT_INT8;       ///< Signed 8 bits data type
typedef unsigned long       NVT_UINTP;      ///< For casting from pointer to unsigned integer type
typedef signed long         NVT_INTP;       ///< For casting from pointer to signed integer type

#else

//For LP32, ILP32 arch
typedef unsigned long long  NVT_UINT64;     ///< Unsigned 64 bits data type
typedef signed long long    NVT_INT64;      ///< Signed 64 bits data type
typedef unsigned long       NVT_UINT32;     ///< Unsigned 32 bits data type
typedef signed long         NVT_INT32;      ///< Signed 32 bits data type
typedef unsigned short      NVT_UINT16;     ///< Unsigned 16 bits data type
typedef signed short        NVT_INT16;      ///< Signed 16 bits data type
typedef unsigned char       NVT_UINT8;      ///< Unsigned 8 bits data type
typedef signed char         NVT_INT8;       ///< Signed 8 bits data type
typedef unsigned long       NVT_UINTP;      ///< For casting from pointer to unsigned integer type
typedef signed long         NVT_INTP;       ///< For casting from pointer to signed integer type

#endif
//@}

/**
    @name       Novatek's floating point integer type
*/
//@{
typedef float               NVT_FLOAT;      ///< Floating point integer
typedef double              NVT_DOUBLE;     ///< Double precision floating point integer
//@}

/**
    @name       Novatek's character type
*/
//@{
typedef char                NVT_CHAR;       ///< Character type (8 bits)
typedef short               NVT_WCHAR;      ///< Wide character type (16 bits)
//@}

/**
    @name       Novatek's bit field type
*/
//@{
typedef unsigned int        NVT_UBITFIELD;  ///< Unsigned bit field
typedef signed int          NVT_BITFIELD;   ///< Signed bit field
//@}

/**
    Novatek's boolean type.

    Novatek's boolean type.
*/
typedef enum
{
    FALSE   = 0,                        ///< Boolean value, FALSE
    TRUE    = 1,                        ///< Boolean value, TRUE

    ENUM_DUMMY(NVT_BOOL)
} NVT_BOOL;

// NULL
#ifndef NULL
#define NULL                ((void*)0)
#endif

// ENABLE, DISABLE
#ifndef DISABLE
#define DISABLE             0
#endif

#ifndef ENABLE
#define ENABLE              1
#endif

/**
    Macro to generate UINT32 value of specific bit
*/
//@{
#define BIT_VALUE32(n)      (((NVT_UINT32)1) << (n))
//@}

//@}

#endif // _NVT_TYPE_H
