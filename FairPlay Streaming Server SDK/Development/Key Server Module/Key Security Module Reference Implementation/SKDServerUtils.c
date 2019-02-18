/*
Copyright (C) 2016 Apple Inc. All Rights Reserved.
 See the Apple Developer Program License Agreement for this file's licensing information.
 All use of these materials is subject to the terms of the Apple Developer Program License Agreement.
 
Abstract:
KSM reference implementation helper functions
*/

#include <stdio.h>
#include <string.h>

#include "PlatformTypes.h"

#include "SKDServer.h"
#include "SKDServerUtils.h"

// openssl includes
/*
 * NOTE: All Crypto in this file assumes the usage of openssl-0.9.8k.
 */
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>

// time includes 
#include <sys/time.h>

/*
 * NOTE: This is the variable to store the Server Private Key in Pem Format.
 * It is used in the SKDServerRSADecryptKey() function. 
 * ADAPT: populate with private key from the SDK package
 */
static const UInt8 pKeyPem[] = {};

Boolean PS_IS_NO_ERROR_FN(
    OSStatus    status,
    const char *var,
    const char *file,
    UInt32      line )
{
    if ( status == noErr )
        return true;

    fprintf(stderr, "Assertion failure: %s == %" PRS32 " [File: %s, Line: %" PRU32 "]\n", var, status, file, line );
    return false;
}


#if PS_DEBUG
void SKDServerDumpSPCContainer(
    SKDServerSPCContainerV1 *spcContainer)
{
    PS_RequireAction(spcContainer != NULL, return;)
    printf("***Dumping Server Playback Context Container: \n");
    printf("Version: %"PRU32"\n", spcContainer->version);
    printf("Size   : %"PRU32"\n", spcContainer->spcDataSize);
    SKDServerDumpBuf("AR: ", spcContainer->spcData.antiReplaySeed, PS_AES128_KEY_SZ);
    SKDServerDumpBuf("HU: ", spcContainer->spcData.hu, PS_V1_HASH_SZ);
    SKDServerDumpBuf("R1: ", spcContainer->spcData.r1, PS_V1_R1_SZ);
    SKDServerDumpBuf("R2: ", spcContainer->spcData.r2, PS_V1_R2_SZ);
    SKDServerDumpBuf("DAS_k: ", spcContainer->spcData.DAS_k, PS_AES128_KEY_SZ);
    SKDServerDumpBuf("SK: ", spcContainer->spcData.sk, PS_AES128_KEY_SZ);
}

void SKDServerDumpBuf(char *str, UInt8 *buf, UInt32 bufSize)
{
    UInt8 myByte;
    UInt32 i;
    fprintf(stderr, "%s\n", str);

    if (NULL != buf)
    {
        for ( i = 0; i < bufSize; i++ )
        {
            myByte = buf[i];
            fprintf(stderr, "0x%02x, ", myByte);
            if ( (i+1) % 16 == 0 )
                fprintf(stderr, "\n");
        }
    }
    
    fprintf(stderr, "\n");
}
#endif // PS_DEBUG

UInt32 SKDServerGetBigEndian32(
    const UInt8 src[4])
{
    return ( src[0] << 24 ) | ( src[1] << 16 ) | ( src[2] << 8 ) | src[3];
}

UInt64 SKDServerGetBigEndian64(
    const UInt8 src[8])
{
    UInt64  ret=0, tmp=0;
    tmp = src[0];
    ret =       ( tmp << 56 );
    tmp = src[1];
    ret = ret | ( tmp << 48 );
    tmp = src[2];
    ret = ret | ( tmp << 40 );
    tmp = src[3];
    ret = ret | ( tmp << 32 );
    tmp = src[4];
    ret = ret | ( tmp << 24 );
    tmp = src[5];
    ret = ret | ( tmp << 16 );
    tmp = src[6];
    ret = ret | ( tmp << 8 );
    tmp = src[7];
    ret = ret |  tmp;
    
    return ret;
}

void SKDServerSetBigEndian32(
    UInt32 x,
    UInt8  dst[4])
{
    dst[0] = (UInt8)( x >> 24 );
    dst[1] = (UInt8)( x >> 16 );
    dst[2] = (UInt8)( x >> 8 );
    dst[3] = (UInt8)x;
}

void SKDServerSetBigEndian64(
    UInt64 x,
    UInt8  dst[8])
{
    dst[0] = (UInt8)( x >> 56 );
    dst[1] = (UInt8)( x >> 48 );
    dst[2] = (UInt8)( x >> 40 );
    dst[3] = (UInt8)( x >> 32 );
    dst[4] = (UInt8)( x >> 24 );
    dst[5] = (UInt8)( x >> 16 );
    dst[6] = (UInt8)( x >> 8 );
    dst[7] = (UInt8)x;
}

static void SKDServerCopyBytes(
    UInt8        *dst, 
    UInt32        dst_ofs, 
    const UInt8  *src, 
    UInt32        src_ofs, 
    UInt32        len)
{
    if (src + src_ofs > dst + dst_ofs)
    {
        UInt32 i = 0;
        while ( i < len )
        { \
            dst[dst_ofs + i] = src[src_ofs + i];
            i++;
        }
    }
    else
    {
        UInt32 i = len;
        while ( i > 0 )
        { \
            i--;
            dst[dst_ofs + i] = src[src_ofs + i];
        }
    }
}
    
OSStatus SKDServerWriteBytes(
    UInt32      *inputOutputBufferOffset, 
    UInt32       nbBytesToWrite,
    const UInt8  inputBuffer[],
    UInt32       outputBufferSize,
    UInt8        outputBuffer[])
{
    OSStatus status = noErr;
    
    UInt32 localOffset = 0;
    
    // sanity check inputs
    PS_RequireAction(inputBuffer      != NULL, return kDRMSKDServerParamErr;)
    PS_RequireAction(outputBuffer     != NULL, return kDRMSKDServerParamErr;)
    PS_RequireAction(outputBufferSize != 0,    return kDRMSKDServerParamErr;)

    if (inputOutputBufferOffset != NULL)
    {
        localOffset = *inputOutputBufferOffset;
    }
    
    PS_RequireAction((localOffset + nbBytesToWrite) <= outputBufferSize, return kDRMSKDServerParamErr;)

    // zero out destination buffer
    memset(outputBuffer + localOffset, 0, nbBytesToWrite);
    
    SKDServerCopyBytes(outputBuffer, localOffset, inputBuffer, 0, nbBytesToWrite);

    if (inputOutputBufferOffset != NULL)
    {
        // increment the inputBufferOffset
        *inputOutputBufferOffset += nbBytesToWrite;
    }
    
    return status;
}

OSStatus SKDServerReadBytes(
    UInt32      *inputOutputBufferOffset, 
    UInt32       nbBytesToRead,
    const UInt8  inputBuffer[],
    UInt32       inputBufferSize,
    UInt8        outputBuffer[])    // allocated by the caller
{
    OSStatus status = noErr;
    
    UInt32 localOffset = 0;
    
    // sanity check inputs
    PS_RequireAction(outputBuffer      != NULL, return kDRMSKDServerParamErr;)
    PS_RequireAction(inputBuffer       != NULL, return kDRMSKDServerParamErr;)
    PS_RequireAction(inputBufferSize   != 0, return kDRMSKDServerParamErr;)
    
    if (inputOutputBufferOffset != NULL)
    {
        localOffset = *inputOutputBufferOffset;
    }
    
    PS_RequireAction((localOffset + nbBytesToRead) <= inputBufferSize, return kDRMSKDServerParamErr;)
    
    // zero out destination buffer
    memset(outputBuffer, 0, nbBytesToRead);
    
    SKDServerCopyBytes(outputBuffer, 0, inputBuffer, localOffset, nbBytesToRead);
    
    if (inputOutputBufferOffset != NULL)
    {
        // increment the inputBufferOffset
        *inputOutputBufferOffset += nbBytesToRead;
    }
    
    return status;
}

static void SKDServerGenRandom4(
    UInt8 data[4])
{
    UInt32 randomNumber = 0;

    if (data != NULL)
    {
      /* 
       * this reference implementation provides an example when the
       * code runs either on Linux.
       * based on your platform you should change the next line
       */
      randomNumber = random();
      SKDServerSetBigEndian32(randomNumber, data);
    }
}

void SKDServerGenRandom16(
    UInt8 data[16])
{
    UInt32 i = 0;
    
    for(i = 0; i < 4; i++)
    {
        SKDServerGenRandom4(&data[i*4]);
    }
}

void SKDServerGenRandom20(
    UInt8 data[20])
{
    UInt32 i = 0;
    
    for(i = 0; i < 5; i++)
    {
        SKDServerGenRandom4(&data[i*4]);
    }
}

/*!
 * This function will aes encrypt or decrypt the input using key and IV.
 *
 * Note the reference implementation uses OpenSSL as crypto engine
 * you should change the implementation when running the code if OpenSSL is not
 * available or not your primary choice.
 *
 * @param[input]      data to encrypt or decrypt
 * @param[output]     encrypted or decrypted data
 * @param[inputSize]  size of data to encrypt
 * @param[key]        key used to do the encryption or decryption
 * @param[iv]         iv used to the encryption or decryption
 * @param[opType]     kSKDServerAESEncrypt, or kSKDServerAESDecrypt
 * @param[opMode]     kSKDServerAES_CBC, or kSKDServerAES_ECB
 */
OSStatus SKDServerAESEncryptDecrypt(
    const UInt8            *input,
    UInt8                  *output,
    UInt32                  inputSize,
    const UInt8             key[PS_AES128_KEY_SZ],
    UInt8                   iv[PS_AES128_KEY_SZ],
    SKDServerAESEncType  opType,
    SKDServerAESEncMode  opMode)
{
    OSStatus status = noErr;
    
    AES_KEY aesKey;
    
    // 1. sanity check inputs
    PS_RequireAction(input      != NULL, return kDRMSKDServerParamErr;)
    PS_RequireAction(inputSize  != 0,    return kDRMSKDServerParamErr;)
    PS_RequireAction(output     != NULL, return kDRMSKDServerParamErr;)
    PS_RequireAction(key        != NULL, return kDRMSKDServerParamErr;)
    
    switch (opType)
    {
        case kSKDServerAESEncrypt:
        {
            AES_set_encrypt_key(key, PS_AES128_KEY_SZ << 3, &aesKey);
            
            switch (opMode)
            {
                case kSKDServerAES_CBC:
                {
                    PS_RequireAction(iv != NULL, return kDRMSKDServerParamErr;)
                    AES_cbc_encrypt(input, output, inputSize, &aesKey, iv, AES_ENCRYPT);
                    break;
                }
                case kSKDServerAES_ECB:
                {
                    PS_RequireAction(inputSize == PS_AES128_KEY_SZ, return kDRMSKDServerParamErr;)
                    AES_ecb_encrypt(input, output, &aesKey, AES_ENCRYPT);
                    break;
                }
                default:
                {
                    PS_SET_ERROR_STATUS(status, kDRMSKDServerParamErr);
                    break;
                }
            }
            break;
        }
        case kSKDServerAESDecrypt:
        {
            AES_set_decrypt_key(key, PS_AES128_KEY_SZ << 3, &aesKey);
            
            switch (opMode)
            {
                case kSKDServerAES_CBC:
                {
                    PS_RequireAction(iv != NULL, return kDRMSKDServerParamErr;)
                    AES_cbc_encrypt(input, output, inputSize, &aesKey, iv, AES_DECRYPT);
                    break;
                }
                case kSKDServerAES_ECB:
                {
                    PS_RequireAction(inputSize == PS_AES128_KEY_SZ, return kDRMSKDServerParamErr;)
                    AES_ecb_encrypt(input, output, &aesKey, AES_DECRYPT);
                    break;
                }
                default:
                {
                    PS_SET_ERROR_STATUS(status, kDRMSKDServerParamErr);
                    break;
                }
            }
            break;
        }
        default:
        {
            PS_SET_ERROR_STATUS(status, kDRMSKDServerParamErr);
            break;
        }
    }
    
    return status;
}

/*
 *  NOTE: This is a place holder for the call to fetch the content key and IV.
 *        Currently this function zeroes out the CK and IV buffers passed in.
 */
OSStatus SKDServerFetchContentKeyAndIV(
    const UInt8 *assetId /* input  */, 
    UInt8  *ck           /* output */,
    UInt8  *iv           /* output */)
{
    OSStatus  status = noErr;
    
    (void) assetId;
    // sanity check inputs
    PS_RequireAction(ck != NULL, return kDRMSKDServerParamErr;)
    PS_RequireAction(iv != NULL, return kDRMSKDServerParamErr;)

    memset(ck, 0, PS_AES128_KEY_SZ);
    memset(iv, 0, PS_AES128_IV_SZ);

    return status;
}

/*
 * NOTE: This function should determine which versions of the protocol the server supports.
 *       Currently the only supported version in the specification is 1.
 */
OSStatus SKDServerGetSupportedVersions(
    UInt32 **versions,
    UInt32 *nbVersions)
{
    OSStatus  status = noErr;
    
    UInt32 *localVersions   = NULL;
    UInt32  nbLocalVersions = 1;
    
    // sanity check inputs
    PS_RequireAction(versions   != NULL, return kDRMSKDServerParamErr;)
    PS_RequireAction(nbVersions != NULL, return kDRMSKDServerParamErr;)

    // server supports v1
    localVersions = malloc(nbLocalVersions * sizeof(UInt32));
    PS_RequireAction(localVersions != NULL, return kDRMSKDServerMemErr;)

    localVersions[0] = 1;

    *versions  = localVersions;
    *nbVersions = nbLocalVersions;

    return status;
}

/*
 *  NOTE: This is a place holder for the call to fetch the ASK.
 *  The ASK is part of the security information Apple will provide.
 *  Currently this function zeroes out the ask buffer passed in.
 */
OSStatus SKDServerGetASK(
    UInt8  ask[PS_AES128_KEY_SZ])
{
    OSStatus  status = noErr;

    // sanity check inputs
    PS_RequireAction(ask != NULL, return kDRMSKDServerParamErr;)

    memset(ask, 0, PS_AES128_KEY_SZ);

    return status;
}

/*
 * NOTE: This function decrypts the aesKey wrapped in the SPC.
 *       The private key used here is in the PEM format.
 *
 * The private key is part of the security information Apple will provide. 
 *
 * The reference implementation uses OpenSSL as crypto engine
 * you should change the implementation when running your code if OpenSSL is not
 * available or not your primary choice.
 */
OSStatus SKDServerRSADecryptKey(
    UInt8  *aesWrappedKey,
    UInt8  *aesKey)
{
    OSStatus status = noErr;
    
    EVP_PKEY *pkeyCtx = NULL;
    BIO      *pKeyBio = NULL;
    RSA      *pKey    = NULL;
    SInt32    ret     = 0;
    
    // 1. sanity check inputs
    PS_RequireAction(aesWrappedKey != NULL, return kDRMSKDServerParamErr;)
    PS_RequireAction(aesKey        != NULL, return kDRMSKDServerParamErr;)

#if PS_DEBUG    
    ERR_load_crypto_strings();
#endif // PS_DEBUG
    
    pKeyBio = BIO_new_mem_buf((void *)pKeyPem, sizeof pKeyPem);
    PS_RequireAction(pKeyBio != NULL, status = kDRMSKDServerOpenSSLErr;)
    
    if (PS_IS_NO_ERROR(status))
    {
        pkeyCtx = PEM_read_bio_PrivateKey(pKeyBio, NULL, NULL, NULL);
        PS_RequireAction(pkeyCtx != NULL, status = kDRMSKDServerOpenSSLErr;)
    
        if (PS_IS_NO_ERROR(status))
        {
            pKey = EVP_PKEY_get1_RSA(pkeyCtx);
            PS_RequireAction(pKey != NULL, status = kDRMSKDServerOpenSSLErr;)
            
            if (PS_IS_NO_ERROR(status))
            {
                ret = RSA_check_key(pKey);
                PS_RequireAction(ret == 1, status = kDRMSKDServerOpenSSLErr;)
                
                if (PS_IS_NO_ERROR(status))
                {
                    ret = RSA_private_decrypt(PS_V1_WRAPPED_KEY_SZ, aesWrappedKey, aesKey, pKey, RSA_PKCS1_OAEP_PADDING);
                    PS_RequireAction(ret == PS_AES128_KEY_SZ, status = kDRMSKDServerOpenSSLErr;)
                }
            }
        }
    }
    
#if PS_DEBUG
    if (kDRMSKDServerOpenSSLErr == status)
    {
        printf("OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
    }
#endif // PS_DEBUG
    
    // clean up    
    if (pkeyCtx != NULL)
    {
         EVP_PKEY_free(pkeyCtx);
         pkeyCtx = NULL;
    }
    
    if (pKeyBio != NULL)
    {
        BIO_free(pKeyBio);
        pKeyBio = NULL;
    }
    
    if (pKey != NULL)
    {
        RSA_free (pKey);
        pKey = NULL;
    }
    
    return status;
}

OSStatus SKDServerDeriveAntiReplayKey(
    UInt8      *arSeed,
    UInt8      *R1,
    UInt32      R1Length,
    UInt8      *ek )
{
    OSStatus    status = noErr;
    SHA_CTX    ctx;
    UInt8       r1_hash[20];
    AES_KEY k;

    PS_RequireAction(arSeed != NULL, return kDRMSKDServerParamErr;)
    PS_RequireAction(R1     != NULL, return kDRMSKDServerParamErr;)

    SHA1_Init(&ctx);
    SHA1_Update(&ctx, R1, R1Length );
    SHA1_Final(r1_hash, &ctx);

    AES_set_encrypt_key(r1_hash, PS_AES128_KEY_SZ << 3, &k);
    AES_ecb_encrypt(arSeed, ek, &k, AES_ENCRYPT);

    return status;
}
