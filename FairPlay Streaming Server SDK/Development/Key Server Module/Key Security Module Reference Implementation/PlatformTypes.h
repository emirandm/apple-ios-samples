/*
Copyright (C) 2016 Apple Inc. All Rights Reserved.
 See the Apple Developer Program License Agreement for this file's licensing information.
 All use of these materials is subject to the terms of the Apple Developer Program License Agreement.
 
Abstract:
Platform dependent types
*/

#ifndef _STANDARD_TYPES_H_
#define _STANDARD_TYPES_H_


#if __linux__ && _LP64
#include <endian.h>
#include <limits.h>
#include <byteswap.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>

#define	RequireNoErr(err, action)				if ((err) != noErr) { action }
#define	AssertNoErr(err)							{}
#define	Assert(condition)							{}

typedef unsigned char                   UInt8;
typedef signed char	                    SInt8;
typedef unsigned short	                UInt16;
typedef signed short                    SInt16;
typedef unsigned int                    UInt32;
typedef signed int	                    SInt32;
typedef unsigned long                   UInt64;
typedef signed long                     SInt64;

typedef SInt32                          OSStatus;
typedef SInt32                          Fixed;

typedef unsigned char                   Boolean;

#ifndef IS_NOERR_DEFINED
#define IS_NOERR_DEFINED
    enum {
        noErr = 0
    };
#endif

    enum {
        nil = 0
    };

#define true	1
#define false	0

#define FOUR_CHAR_CODE(x)           (x)

    #if __LITTLE_ENDIAN
    #define EndianU64_BtoN(x)           __bswap_64 (x)
    #define EndianU32_BtoN(x)           __bswap_32 (x)
    #define EndianU16_BtoN(x)           __bswap_16 (x)
    #define EndianU64_NtoB(x)           __bswap_64 (x)
    #define EndianU32_NtoB(x)           __bswap_32 (x)
    #define EndianU16_NtoB(x)           __bswap_16 (x)
    #define EndianU32_LtoN(x)             (x)

    #define EndianS32_BtoN(x)           (SInt32)EndianU32_BtoN(x)

    #define CFSwapInt64BigToHost(x)	__bswap_64 (x)
    #define CFSwapInt32BigToHost(x)	__bswap_32 (x)
    #define CFSwapInt16BigToHost(x)	__bswap_16 (x)
    #define CFSwapInt64HostToBig(x)	__bswap_64 (x)
    #define CFSwapInt32HostToBig(x)	__bswap_32 (x)
    #define CFSwapInt16HostToBig(x)	__bswap_16 (x)

    #else // __BIG_ENDIAN
    #error "Error!! Linux is not Big Endian. Check the toolchain!!!"
    #endif /* __LITTLE_ENDIAN__ */

#else // __linux__ && _LP64

    #include <CoreFoundation/CFBase.h>
    // For MacOS
    #if __x86_64
    #define HAVE_ARCH_X86_64    1
    #endif

#endif /* __linux__ && _LP64 */

#ifndef PRINT_MACROS
#define PRINT_MACROS
    #if HAVE_ARCH_X86_64
        #define PRNATIVE "ld"
        #define PRU16   "u"
        #define PRS32   "d"
        #define PRU32   "u"
        #define PRX32   "X"
        #if __linux__ && _LP64
            #define PRU64   "lu"
            #define PRS64   "ld"
            #define PRX64   "lX"
        #else
            #define PRU64   "llu"
            #define PRS64   "lld"
            #define PRX64   "llX"
        #endif
    #else
        #define PRNATIVE "d"
        #define PRU16   "u"
        #define PRS32   "ld"
        #define PRU32   "lu"
        #define PRX32   "lX"
        #define PRU64   "llu"
        #define PRS64   "lld"
        #define PRX64   "llX"
    #endif
#endif // PRINT_MACROS


#endif /* _STANDARD_TYPES_H_ */
