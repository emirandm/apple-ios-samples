/*
Copyright (C) 2016 Apple Inc. All Rights Reserved.
 See the Apple Developer Program License Agreement for this file's licensing information.
 All use of these materials is subject to the terms of the Apple Developer Program License Agreement.

Abstract:
KSM reference implementation helper function prototypes
*/

#ifndef SKD_SERVER_UTILS_H_
#define SKD_SERVER_UTILS_H_

// PS_DEBUG can be 0 or 1
// setting PS_DEBUG to 1 will print/dump usefull debug info
#define PS_DEBUG                  0
#define PS_FIXED_RANDOMS          DEBUG

#define PS_NB_HARDCODED_KEYS      11

#define PS_RequireAction(condition, action)            if (!(condition)) { fprintf(stderr, "Assertion failure: %s [File: %s, Line: %d] ]\n", #condition, __FILE__, __LINE__); action }
#define PS_IS_NO_ERROR(err)                            PS_IS_NO_ERROR_FN( (err), #err, __FILE__, __LINE__ )
#define PS_SET_ERROR_STATUS(var, err)                  PS_IS_NO_ERROR_FN( (var) = (err), #var, __FILE__, __LINE__ )

typedef enum {
    kSKDServerAESEncrypt = 0,
    kSKDServerAESDecrypt             
} SKDServerAESEncType;

typedef enum {
    kSKDServerAES_CBC = 0,
    kSKDServerAES_ECB            
} SKDServerAESEncMode;  

Boolean PS_IS_NO_ERROR_FN(
OSStatus    status,
const char *var,
const char *file,
UInt32      line ); 

#if PS_DEBUG
void SKDServerDumpSPCContainer(SKDServerSPCContainerV1 *spcContainer);
void SKDServerDumpBuf(char *str, UInt8 *buf, UInt32 bufSize);
#define SKDServerPrint(str) SKDServerDumpBuf((str), NULL, 0)
#else
#define SKDServerDumpSPCContainer(a)
#define SKDServerDumpBuf(a, b, c)
#define SKDServerPrint(str)
#endif

// generates 16 random bytes
void SKDServerGenRandom16(
    UInt8 data[16]);

// generates 20 random bytes
void SKDServerGenRandom20(
    UInt8 data[20]);
 
// 
OSStatus SKDServerRSADecryptKey(
    UInt8  *aesWrappedKey,
    UInt8  *aesKey);
    
OSStatus SKDServerAESEncryptDecrypt(
    const UInt8         *input,
    UInt8               *output,
    UInt32               inputSize,
    const UInt8          key[PS_AES128_KEY_SZ],
    UInt8                iv[PS_AES128_IV_SZ],
    SKDServerAESEncType  opType,
    SKDServerAESEncMode  opMode);

OSStatus SKDServerFetchContentKeyAndIV(
    const UInt8 *assetId /* input  */, 
    UInt8  *ck           /* output */,
    UInt8  *iv           /* output */);

OSStatus SKDServerGetSupportedVersions(
    UInt32 **versions,
    UInt32 *nbVersions);
    
OSStatus SKDServerGetASK(
    UInt8  ask[PS_AES128_KEY_SZ]);

UInt32 SKDServerGetBigEndian32(
    const UInt8 src[4]);

UInt64 SKDServerGetBigEndian64(
    const UInt8 src[8]);
    
void SKDServerSetBigEndian32(
    UInt32 x,
    UInt8  dst[4]);    

void SKDServerSetBigEndian64(
    UInt64 x,
    UInt8  dst[8]);
        
OSStatus SKDServerReadBytes(
    UInt32      *inputOutputBufferOffset, 
    UInt32       nbBytesToRead,
    const UInt8  inputBuffer[],
    UInt32       inputBufferSize,
    UInt8        outputBuffer[]);

OSStatus SKDServerWriteBytes(
    UInt32      *inputOutputBufferOffset, 
    UInt32       nbBytesToWrite,
    const UInt8  inputBuffer[],
    UInt32       outputBufferSize,
    UInt8        outputBuffer[]);

OSStatus SKDServerDeriveAntiReplayKey(
    UInt8      *arSeed,
    UInt8      *R1,
    UInt32      R1Length,
    UInt8      *ek );
    
#endif // SKD_SERVER_UTILS_H_
