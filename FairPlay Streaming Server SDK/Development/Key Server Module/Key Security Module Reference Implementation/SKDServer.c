/*
Copyright (C) 2016 Apple Inc. All Rights Reserved.
 See the Apple Developer Program License Agreement for this file's licensing information.
 All use of these materials is subject to the terms of the Apple Developer Program License Agreement.
 
Abstract:
KSM reference implementation
*/

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "PlatformTypes.h"
#include "SKDServer.h"
#include "SKDServerUtils.h"

// crypto includes
#include "SKDServerD.h"

//
//------------------------------------------------------------------------------
#if 0
#pragma mark -
#pragma mark Secure Key DeliverySKD Server Internal Structures
#endif
//------------------------------------------------------------------------------
//
    
typedef struct {
    UInt32                totalSize;
    UInt32                valueSize;
    UInt8                *valueData;
} SKDServerTLLV;

typedef struct {
    UInt8                 scratch_4[4];
    UInt8                 scratch_8[8];
    UInt32                currentOffset;
} SKDServerParser;

typedef struct {
    SKDServerParser    parser;
    SKDServerTLLV     *TLLVs;
    UInt32             nbTLLVs;
    UInt32             presenceFlags;
} SKDServerSPCDataV1Parser;

typedef struct {
    UInt32               *versions;
    UInt32                nbVersions;
} SKDServerSupportedVerions;

typedef struct SKDServerClientRefTime_ {
    UInt32              date;  /* first play back date expressed in seconds elapsed since 1970-01-01T00:00:00Z */
    UInt32              playback; 
    UInt64              playbackId;
}SKDServerClientRefTime;

typedef struct {
    UInt8                         antiReplaySeed[PS_AES128_KEY_SZ];
    UInt8                         DAS_k[PS_AES128_KEY_SZ];
    UInt8                         sk[PS_AES128_KEY_SZ];
    UInt8                         hu[PS_V1_HASH_SZ];
    UInt8                         r2[PS_V1_R2_SZ];
    UInt8                         r1[PS_V1_R1_SZ];
    UInt8                         sk_r1_integrity_tag[PS_V1_SKR1_INTEGRITY_SZ];
    UInt8                         sk_r1_integrity[PS_V1_SKR1_INTEGRITY_SZ];
    UInt8                         sk_r1[PS_V1_SKR1_SZ];
    UInt32                        p_version_used;
    SKDServerSupportedVerions     p_version_supported;
    SKDServerTLLV                *returnTLLVs;
    UInt32                        nbReturnTLLVs;
    SKDServerSPCDataV1Parser      spcDataParser;
    SKDServerClientRefTime        playInfo;
} SKDServerSPCDataV1;

typedef struct {
    UInt32                 version;
    UInt8                  aesKeyIV       [PS_AES128_IV_SZ];
    UInt8                  aesWrappedKey  [PS_V1_WRAPPED_KEY_SZ];
    UInt8                  certificateHash[PS_V1_HASH_SZ];
    UInt8                 *spcDecryptedData;
    UInt32                 spcDataSize;
    UInt32                 spcDataOffset;
    SKDServerSPCDataV1     spcData;
    SKDServerParser        parser;
} SKDServerSPCContainerV1;

typedef struct {
    UInt32 leaseDuration;
    UInt32 rentalDuration;
    UInt32 playbackDuration;
    UInt32 keyType;
    UInt32 reserved;
} SKDServerKeyDuration;

typedef enum SKDClientRefTimePlayback_{
    kCurrentlyPlayingCKNotRequired      = 0xa5d6739e,
    kFirstPlaybackCKRequired            = 0xf4dee5a2,
    kCurrentlyPlayingCKRequired         = 0x4f834330,
    kPlaybackSessionStopped             = 0x5991bf20,
}SKDClientRefTimePlayback;

typedef enum SKDLeaseRentalType_{
    kKeyTypeLease                   = 0x1a4bde7e,
    kKeyTypeDuration                = 0x3dfe45a0,
    kKeyTypeLeaseAndDuration        = 0x27b59bde,
    kKeyTypePersistence             = 0x3df2d9fb,
    kKeyTypePersistenceAndDuration  = 0x18f06048,
} SKDLeaseRentalType;

typedef struct {
    UInt32                 tag_ck_TotalSize;
    UInt8                  ck[PS_AES128_KEY_SZ];
    UInt8                  iv[PS_AES128_IV_SZ];
    UInt32                 tag_r1_TotalSize;
    UInt8                  r1[PS_V1_R1_SZ];
    SKDServerParser        parser;
    SKDServerKeyDuration   keyDuration;
} SKDServerCKCDataV1;

typedef struct {
    UInt32                 version;
    UInt8                  aesKeyIV       [PS_AES128_IV_SZ];
    UInt8                 *ckcDataPtr;
    UInt32                 ckcDataSize;
    SKDServerCKCDataV1     ckcData;
    SKDServerParser        parser;
} SKDServerCKCContainerV1;

typedef struct {
    SKDServerSPCContainerV1    spcContainer;
    SKDServerCKCContainerV1    ckcContainer;
    const UInt8               *assetId;
    UInt32                     leaseDuration;
    UInt32                     rentalDuration;
    UInt32                     playbackDuration;
    Boolean                    persistence;
    UInt32                     persistenceDuration;
} SKDServerCtxV1;

//
//------------------------------------------------------------------------------
#if 0
#pragma mark -
#pragma mark Secure Key Delivery Server Internal helper functions
#endif
//------------------------------------------------------------------------------
//

static OSStatus SKDServerDecryptSK_R1(
    SKDServerSPCDataV1 *spcData)
{
    OSStatus status = noErr;
    
    PS_RequireAction(spcData != NULL, return kDRMSKDServerParamErr;)

    UInt8  decryptedSK_R1[PS_V1_SKR1_SZ] = {0};
    UInt32 localOffset = 0;
    
    // 1. decrypt [SK...R1]
    UInt8   aesIV[PS_AES128_IV_SZ];
    
    // 1.1 get the IV
    status = SKDServerReadBytes(
                NULL, PS_AES128_IV_SZ, 
                spcData->sk_r1, sizeof spcData->sk_r1, aesIV);
    
    if (PS_IS_NO_ERROR(status))
    {
        status = SKDServerAESEncryptDecrypt(
                    &spcData->sk_r1[PS_AES128_IV_SZ], 
                    decryptedSK_R1, PS_V1_SKR1_SZ, 
                    spcData->DAS_k, aesIV, 
                    kSKDServerAESDecrypt, kSKDServerAES_CBC);
    
        // 2. parse SK, HU, and R1
        // 2.1 parse SK
        if (PS_IS_NO_ERROR(status))
        {
            status = SKDServerReadBytes(
                        &localOffset, PS_AES128_KEY_SZ, 
                        decryptedSK_R1, PS_V1_SKR1_SZ, spcData->sk);
            
            // 2.2 parse HU
            if (PS_IS_NO_ERROR(status))
            {
                status = SKDServerReadBytes(
                            &localOffset, PS_V1_HASH_SZ, 
                            decryptedSK_R1, PS_V1_SKR1_SZ, spcData->hu);
                
                // 2.3 parse R1
                if (PS_IS_NO_ERROR(status))
                {
                    status = SKDServerReadBytes(
                                &localOffset, PS_V1_R1_SZ, 
                                decryptedSK_R1, PS_V1_SKR1_SZ, spcData->r1);
                    
                    // 2.4 parse [SK...R1] integrity
                    if (PS_IS_NO_ERROR(status))
                    {
                        status = SKDServerReadBytes(
                                    &localOffset, PS_V1_SKR1_INTEGRITY_SZ, 
                                    decryptedSK_R1, PS_V1_SKR1_SZ, spcData->sk_r1_integrity);
                    }
                }
            }
        }
    }
    
    return status;
}

static OSStatus SKDServerParseSupportedVersions(
    SKDServerSupportedVerions *supportedVersions, 
    SKDServerTLLV             *tllv)
{
    OSStatus status = noErr;
    
    UInt32   currentOffset = 0;
    UInt8    currentVersion[PS_V1_VERSION_SZ] = {0};
    UInt32  *tmp = NULL;

    PS_RequireAction(supportedVersions != NULL, return kDRMSKDServerParamErr;)
    PS_RequireAction(tllv              != NULL, return kDRMSKDServerParamErr;)
    
    // 2. loop through the supported version tag and store them
    while((currentOffset < tllv->valueSize) && (status == noErr))
    {
        status = SKDServerReadBytes(&currentOffset, PS_V1_VERSION_SZ, tllv->valueData, tllv->valueSize, currentVersion);
        
        if (PS_IS_NO_ERROR(status))
        {
            tmp = realloc(supportedVersions->versions, (supportedVersions->nbVersions+1) * (PS_V1_VERSION_SZ));

            if (tmp == NULL)
            {
                PS_SET_ERROR_STATUS(status, kDRMSKDServerMemErr);
            }
            else 
            {
                supportedVersions->versions = tmp;
                supportedVersions->versions[supportedVersions->nbVersions] = SKDServerGetBigEndian32(currentVersion);
                supportedVersions->nbVersions++;
            }
        }
    }
    
    return status;
}

static OSStatus SKDServerGetMaxIntersectionVersion(
    SKDServerSupportedVerions *serverSupportedVersions,
    SKDServerSupportedVerions *clientSupportedVersions,
    UInt32                    *maxVersion)
{
    OSStatus status = noErr;
    UInt32   i = 0, j = 0, localMaxVersion = 0;
    UInt32  *versionsIntersection = NULL, *tmp = NULL;
    UInt32   intersectionSize     = 0;
    
    PS_RequireAction(serverSupportedVersions != NULL, return kDRMSKDServerParamErr;)
    PS_RequireAction(clientSupportedVersions != NULL, return kDRMSKDServerParamErr;)
    PS_RequireAction(maxVersion              != NULL, return kDRMSKDServerParamErr;)
    
    // 1. find the intersection of the server & client versions 
    for(i = 0; ((i < serverSupportedVersions->nbVersions) && (status == noErr)); i++)
    {
        for(j = 0; ((j < clientSupportedVersions->nbVersions) && (status == noErr)); j++)
        {
            if (serverSupportedVersions->versions[i] == clientSupportedVersions->versions[j])
            {
                tmp = realloc(versionsIntersection, (intersectionSize + 1) * PS_V1_VERSION_SZ );
                
                if (tmp == NULL)
                {
                    PS_SET_ERROR_STATUS(status, kDRMSKDServerMemErr);
                }
                else 
                {
                    versionsIntersection = tmp;
                    versionsIntersection[intersectionSize] = serverSupportedVersions->versions[i];
                    intersectionSize++;
                }
                break;
            }
        }
    }
    
    if (PS_IS_NO_ERROR(status))
    {
        // 2. find the max version in the intersection of versions
        if (intersectionSize > 0)
        {
            for(i = 0; i < intersectionSize; i++)
            {
                if (versionsIntersection[i] > localMaxVersion)
                {
                    localMaxVersion = versionsIntersection[i];
                }
            }  
        }
        else 
        {
            PS_SET_ERROR_STATUS(status, kDRMSKDServerVersionErr);
        }
    }
    
    *maxVersion = localMaxVersion;
    
    if (versionsIntersection != NULL)
    {
        free(versionsIntersection);
        versionsIntersection = NULL;
    }
    
    return status;
}

static OSStatus SKDServerCheckUsedVersion(
    SKDServerSPCDataV1 *spcData)
{
    OSStatus status = noErr;
    
    SKDServerSupportedVerions serverSupportedVersions;
    UInt32                       maxVersion = 0;
    
    PS_RequireAction(spcData != NULL, return kDRMSKDServerParamErr;)
    
    // 3. make sure the used version is max of the intersection of server & client supported versions
    // 3.1 get the list of the server supported versions (see Figure 2-19 of the SKD server SKDspecification)
    status = SKDServerGetSupportedVersions(
                &serverSupportedVersions.versions, 
                &serverSupportedVersions.nbVersions);
                
    if (PS_IS_NO_ERROR(status))
    {
        // 3.2 get max version of the intersection of server and client versions 
        status = SKDServerGetMaxIntersectionVersion(&serverSupportedVersions, &spcData->p_version_supported, &maxVersion);
        
        if (PS_IS_NO_ERROR(status))
        {
            // Best practice check per chapter 2 of the SKD server SKDspecification
            PS_RequireAction(spcData->p_version_used == maxVersion, return kDRMSKDServerVersionErr;)
        }
    }
    
    return status;
}

static OSStatus SKDServerExtractReturnTags(
    SKDServerTLLV      *returnRequest,
    SKDServerSPCDataV1 *spcData)    
{
    OSStatus status = noErr;
    
    UInt32            i             = 0;
    UInt32            iterOffset    = 0;
    UInt32            result        = 0;
    UInt8             tagBytes[PS_TLLV_TAG_SZ] = {0};
    SKDServerTLLV    *tmpTLLV = NULL;

    PS_RequireAction(spcData                      != NULL, return kDRMSKDServerParamErr;)
    // spcData->spcDataParser.TLLVs is always allocated in SKDServerParseSPCData
    PS_RequireAction(spcData->spcDataParser.TLLVs != NULL, return kDRMSKDServerParamErr;)
    PS_RequireAction(returnRequest                != NULL, return kDRMSKDServerParamErr;)
    
    // 1. iterate on list of TLLVs and extract the tags to be returned based on the returnRequest TLLV
    while ((iterOffset < returnRequest->valueSize) && (status == noErr))
    {
        // 1.1 read the requested tag value
        status = SKDServerReadBytes(
                    &iterOffset, PS_TLLV_TAG_SZ, 
                    returnRequest->valueData, returnRequest->valueSize, tagBytes);
        
        if (PS_IS_NO_ERROR(status))
        {
            // 1.2 find that tag in the list of incoming TLLVs from the SPC
            for (i = 0; i < spcData->spcDataParser.nbTLLVs; i++)
            {                      
                result = memcmp(spcData->spcDataParser.TLLVs[i].valueData - PS_TLLV_HEADER_SZ, tagBytes, PS_TLLV_TAG_SZ);
                
                if (result == 0)
                {
                    SKDServerDumpBuf("Value of tag to be returned: ", spcData->spcDataParser.TLLVs[i].valueData - PS_TLLV_HEADER_SZ, PS_TLLV_TAG_SZ);
            
                    // found the requested tag, copy it into localReturnReqTags pointer
                    tmpTLLV = realloc( spcData->returnTLLVs ,
                                       (spcData->nbReturnTLLVs + 1) * sizeof(SKDServerTLLV));
                    if (tmpTLLV == NULL)
                    {
                        PS_SET_ERROR_STATUS(status, kDRMSKDServerMemErr);
                    }
                    else 
                    {
                        spcData->returnTLLVs = tmpTLLV;
                        // now copy the tag
                        spcData->returnTLLVs[spcData->nbReturnTLLVs].totalSize = spcData->spcDataParser.TLLVs[i].totalSize;
                        spcData->returnTLLVs[spcData->nbReturnTLLVs].valueSize = spcData->spcDataParser.TLLVs[i].valueSize;
                        spcData->returnTLLVs[spcData->nbReturnTLLVs].valueData = spcData->spcDataParser.TLLVs[i].valueData;
                        
                        spcData->nbReturnTLLVs++;
                    }
                    
                    break;
                }
            }
            
            // A tag from the SPC data that is to be returned in the CKC was not found in the SPC!
            if (result != 0)
            {
                PS_SET_ERROR_STATUS(status, kDRMSKDServerMissingRequiredTag);
            }
        }
    }
    
    return status;
}

static OSStatus SKDServerComputeCKCSize(
    const SKDServerSPCDataV1 *spcData,
    SKDServerCKCContainerV1  *ckcContainer)
{
    OSStatus status = noErr;
    
    UInt32 localSize = 0, i = 0;
    
    PS_RequireAction(spcData != NULL, return kDRMSKDServerParamErr;)
    PS_RequireAction(ckcContainer != NULL, return kDRMSKDServerParamErr;)
    
    // 2.1 compute the fixed size
    localSize += PS_TLLV_HEADER_SZ + PS_AES128_IV_SZ + PS_AES128_KEY_SZ +   /* CK TLLV: header bytes, IV bytes, key bytes */
                 PS_TLLV_HEADER_SZ + PS_V1_R1_SZ     + PS_V1_R1_PADDING_SZ; /* R1 TLLV: header bytes, R1 bytes, padding */
    
    // 2.2 compute the size of the tags mentioned in the return request tag
    for (i = 0; i < spcData->nbReturnTLLVs; i++)
    {
        localSize += PS_TLLV_HEADER_SZ + spcData->returnTLLVs[i].totalSize;
    }
    
    if (((spcData->spcDataParser.presenceFlags & FLAG_TAG_CLIENT_REF_TIME) != 0) && /* condition to check for presence of valid keyduration tag */
        (ckcContainer->ckcData.keyDuration.keyType != 0) )                          /* if key type is set then add key duration TLLV size */
    {
        // IMPORTANT: only iOS 11.0 and higher clients support "Offline Key TLLV".
        // For older clients the server should continue using "Key Duration TLLV"
        
        if(( /* ADAPT: verify client iOS version >= 11.0*/ true ) &&
           ((ckcContainer->ckcData.keyDuration.keyType == kKeyTypePersistence) || (ckcContainer->ckcData.keyDuration.keyType == kKeyTypePersistenceAndDuration)) )
        {
            // use "Offline Key TLLV"
            localSize += PS_TLLV_HEADER_SZ + PS_TLLV_OFFLINEKEY_VALUE_SZ + PS_TLLV_OFFLINEKEY_PADDING_SZ; /* Offline Key TLLV: header bytes, value bytes, padding */
        }
        else
        {
            // use "Key Duration TLLV"
            localSize += PS_TLLV_HEADER_SZ + PS_TLLV_DURATION_VALUE_SZ + PS_TLLV_DURATION_PADDING_SZ; /* Key Duration TLLV: header bytes, value bytes, padding */
        }
    }
    
    ckcContainer->ckcDataSize = localSize;
    
    return status;
}

static OSStatus SKDServerParseTLLV(
    SKDServerSPCDataV1Parser *spcDataParser,
    UInt8                       *dataToparse,
    UInt32                       dataToParseSize)
{
    OSStatus status = noErr;
    
    PS_RequireAction(spcDataParser        != NULL, return kDRMSKDServerParamErr;)
    PS_RequireAction(spcDataParser->TLLVs != NULL, return kDRMSKDServerParamErr;)
    PS_RequireAction(dataToparse          != NULL, return kDRMSKDServerParamErr;)
    
    // first, read the total size of the data(L1) (value length + padding length)
    status = SKDServerReadBytes(
                &spcDataParser->parser.currentOffset,
                PS_TLLV_TOTAL_LENGTH_SZ, dataToparse,
                dataToParseSize, spcDataParser->parser.scratch_4);

    if (PS_IS_NO_ERROR(status))
    {
        spcDataParser->TLLVs[spcDataParser->nbTLLVs].totalSize = SKDServerGetBigEndian32(spcDataParser->parser.scratch_4);
        
        // second, read the size of the value(L2)
        status = SKDServerReadBytes(
                    &spcDataParser->parser.currentOffset,
                    PS_TLLV_VALUE_LENGTH_SZ, dataToparse, 
                    dataToParseSize, spcDataParser->parser.scratch_4);
        
        if (PS_IS_NO_ERROR(status))
        {
            spcDataParser->TLLVs[spcDataParser->nbTLLVs].valueSize = SKDServerGetBigEndian32(spcDataParser->parser.scratch_4);
            
            // finally, point the parser's value data pointer to the value stored in the TLLV being parsed.
            spcDataParser->TLLVs[spcDataParser->nbTLLVs].valueData = dataToparse + spcDataParser->parser.currentOffset;
            
            // jump to the next TLLV 
            spcDataParser->parser.currentOffset += spcDataParser->TLLVs[spcDataParser->nbTLLVs].totalSize;
            
            // increase nbTLLVs
            spcDataParser->nbTLLVs++;
        }
    }
    
    return status;
}

static OSStatus SKDServerSetTLLVSizes( 
    UInt8  *buf,
    UInt32 *bufOffset,
    UInt32  totalSize,
    UInt32  valueSize)
{
    OSStatus status = noErr;
    
    PS_RequireAction(buf       != NULL, return kDRMSKDServerParamErr;)
    PS_RequireAction(bufOffset != NULL, return kDRMSKDServerParamErr;)
    
    // 1.2 insert total size
    SKDServerSetBigEndian32(totalSize, buf + *bufOffset);
    *bufOffset += PS_TLLV_TOTAL_LENGTH_SZ;
    
    // 1.3 insert value size
    SKDServerSetBigEndian32(valueSize, buf + *bufOffset);
    *bufOffset += PS_TLLV_VALUE_LENGTH_SZ;
    
    return status;
}

static OSStatus SKDServerSerializeTLLV(
    SKDServerTagValue        tagValue,
    UInt32                   tagValueSize,
    UInt8                   *tagValueData,
    UInt32                   tagPaddingSize,
    UInt8                   *tagPaddingData,
    SKDServerCKCContainerV1 *ckcContainer)
{
    OSStatus status = noErr;
    
    UInt8 tagBytes[PS_TLLV_TAG_SZ] = {0};

    PS_RequireAction(ckcContainer != NULL, return kDRMSKDServerParamErr;)
    
    // 1. body
    SKDServerSetBigEndian64(tagValue, tagBytes);
    
    status = SKDServerWriteBytes(
                &ckcContainer->ckcData.parser.currentOffset, PS_TLLV_TAG_SZ, 
                tagBytes, ckcContainer->ckcDataSize, ckcContainer->ckcDataPtr);
    
    if (PS_IS_NO_ERROR(status))
    {
        status = SKDServerSetTLLVSizes(
                    ckcContainer->ckcDataPtr, 
                    &ckcContainer->ckcData.parser.currentOffset, 
                    tagValueSize + tagPaddingSize, tagValueSize);
                    
        if (PS_IS_NO_ERROR(status))
        {
            // 2. body
            // 2.1 body data
            status = SKDServerWriteBytes(
                        &ckcContainer->ckcData.parser.currentOffset, 
                        tagValueSize, tagValueData, 
                        ckcContainer->ckcDataSize, ckcContainer->ckcDataPtr);
                        
            if (PS_IS_NO_ERROR(status) && (tagPaddingData != NULL) && (tagPaddingSize != 0))
            {
                // 2.2 body padding
                status = SKDServerWriteBytes(
                    &ckcContainer->ckcData.parser.currentOffset, 
                    tagPaddingSize, tagPaddingData, 
                    ckcContainer->ckcDataSize, ckcContainer->ckcDataPtr);
            }
        }
    }
                                    
    return status;
}

static OSStatus SKDServerConstructAndSerializeTLLV(
    SKDServerTagValue              tagValue,
    SKDServerCKCContainerV1       *ckcContainer,
    const SKDServerSPCDataV1      *spcData)
{
    OSStatus status = noErr;
        
    PS_RequireAction(ckcContainer != NULL, return kDRMSKDServerParamErr;)
    PS_RequireAction(spcData      != NULL, return kDRMSKDServerParamErr;)
    
    switch (tagValue)
    {
        case kSKDServerTagCK:
        {
            UInt8 iv_ck[PS_AES128_IV_SZ + PS_AES128_KEY_SZ] = {0};

            status = SKDServerReadBytes(NULL, PS_AES128_IV_SZ, ckcContainer->ckcData.iv, PS_AES128_IV_SZ, iv_ck);
            
            if (PS_IS_NO_ERROR(status))
            {
                status = SKDServerReadBytes(NULL, PS_AES128_KEY_SZ, ckcContainer->ckcData.ck, PS_AES128_KEY_SZ, &iv_ck[PS_AES128_IV_SZ]);
                
                if (PS_IS_NO_ERROR(status))
                {
                    status = SKDServerSerializeTLLV(
                                    kSKDServerTagCK,
                                    PS_AES128_IV_SZ + PS_AES128_KEY_SZ, iv_ck,
                                    0, NULL,
                                    ckcContainer);
                }
            }
            break;
        }
            
        case kSKDServerTagR1:
        {
            UInt8 padding[PS_V1_R1_PADDING_SZ];
            
            SKDServerGenRandom20(padding);
            
            status = SKDServerSerializeTLLV(
                            kSKDServerTagR1,
                            PS_V1_R1_SZ, ckcContainer->ckcData.r1,
                            PS_V1_R1_PADDING_SZ, padding,
                            ckcContainer);
            break;
        }

        case kSKDServerReturnTags:
        {
            // loop through the return tags and serialize them
            UInt64 retTagValue = 0;
            UInt32 i = 0;

            for (i = 0; ((i < spcData->nbReturnTLLVs) && (PS_IS_NO_ERROR(status))); i++)
            {
                retTagValue = SKDServerGetBigEndian64(spcData->returnTLLVs[i].valueData - PS_TLLV_HEADER_SZ);
                
                // return the entire TLLV as sent by the client (value+padding)
                status = SKDServerSerializeTLLV(
                            retTagValue,
                            spcData->returnTLLVs[i].valueSize, spcData->returnTLLVs[i].valueData,
                            spcData->returnTLLVs[i].totalSize - spcData->returnTLLVs[i].valueSize, 
                            spcData->returnTLLVs[i].valueData + spcData->returnTLLVs[i].valueSize,
                            ckcContainer);
            }
            break;
        }
        case kSKDServerKeyDurationTag:
        {
            UInt32  offset = 0;
            UInt8   keyDuration[PS_TLLV_DURATION_VALUE_SZ] = {0};
            UInt8   padding[PS_TLLV_DURATION_PADDING_SZ];
            
            SKDServerSetBigEndian32(ckcContainer->ckcData.keyDuration.leaseDuration, &keyDuration[offset]);
            offset += PS_TLLV_DURATION_LEASE_SZ;
            
            SKDServerSetBigEndian32(ckcContainer->ckcData.keyDuration.rentalDuration, &keyDuration[offset]);
            offset += PS_TLLV_DURATION_CK_SZ;
            
            SKDServerSetBigEndian32(ckcContainer->ckcData.keyDuration.keyType, &keyDuration[offset]);
            offset += PS_TLLV_DURATION_KEY_TYPE_SZ;
            
            SKDServerSetBigEndian32(ckcContainer->ckcData.keyDuration.reserved, &keyDuration[offset]);
            offset += PS_TLLV_DURATION_RESV_SZ;
            
            SKDServerGenRandom16(padding);
            
            status = SKDServerSerializeTLLV(
                        kSKDServerKeyDurationTag,
                        PS_TLLV_DURATION_VALUE_SZ,
                        keyDuration,
                        PS_TLLV_DURATION_PADDING_SZ,
                        padding,
                        ckcContainer);
            break;
        }
        case kSKDServerOfflineKeyTag:
        {
            UInt32  offlineKeyTLLVVersion = PS_TLLV_OFFLINEKEY_TLLV_VERSION;
            UInt32  offset = 0;
            UInt32  reserved = 0;
            UInt8   offlineKeyTLLV[PS_TLLV_OFFLINEKEY_VALUE_SZ] = {0};
            UInt8   padding[PS_TLLV_OFFLINEKEY_PADDING_SZ];
            
            // version field goes first
            SKDServerSetBigEndian32( offlineKeyTLLVVersion, &offlineKeyTLLV[offset] );
            offset += sizeof( UInt32 );
            
            // reserved
            SKDServerSetBigEndian32(reserved, &offlineKeyTLLV[offset]);
            offset += sizeof( UInt32 );
            
            // ADAPT: Set content ID, 16 bytes
            // Unique content ID of the downloaded asset assigned by the server. This value will be returned to the server in Sync TLLV.
            // memcpy( &offlineKeyTLLV[offset], <unique-content-ID>, PS_TLLV_OFFLINEKEY_CONTENTID_SZ );
            offset += PS_TLLV_OFFLINEKEY_CONTENTID_SZ;
            
            // storage duration. How long the content can be playable after the download
            SKDServerSetBigEndian32( ckcContainer->ckcData.keyDuration.rentalDuration, &offlineKeyTLLV[offset]);
            offset += sizeof( UInt32 );
            
            // playback duration. How soon content expires after the first playback
            SKDServerSetBigEndian32( ckcContainer->ckcData.keyDuration.playbackDuration, &offlineKeyTLLV[offset]);
            offset += sizeof( UInt32 );
            
            SKDServerGenRandom16(padding);
            
            status = SKDServerSerializeTLLV(
                                            kSKDServerOfflineKeyTag,
                                            PS_TLLV_OFFLINEKEY_VALUE_SZ,
                                            offlineKeyTLLV,
                                            PS_TLLV_OFFLINEKEY_PADDING_SZ,
                                            padding,
                                            ckcContainer);
            break;
        }
        default:
            break;
    }
    
    return status;
}

static void SKDServerDestroyCtx(SKDServerCtxV1 *serverCtx)
{
    // clean up intermediate allocations
    if (serverCtx != NULL)
    {
        // 1. clean up ckc data ptr
        if (serverCtx->ckcContainer.ckcDataPtr != NULL)
        {
            free(serverCtx->ckcContainer.ckcDataPtr);
            serverCtx->ckcContainer.ckcDataPtr = NULL;
        }
        
        // 2. clean up spc data ptr
        if (serverCtx->spcContainer.spcDecryptedData != NULL)
        {
            free(serverCtx->spcContainer.spcDecryptedData);
            serverCtx->spcContainer.spcDecryptedData = NULL;
        }
        
        if (serverCtx->spcContainer.spcData.spcDataParser.TLLVs != NULL)
        {
            free(serverCtx->spcContainer.spcData.spcDataParser.TLLVs);
            serverCtx->spcContainer.spcData.spcDataParser.TLLVs = NULL;
        }
        
        if (serverCtx->spcContainer.spcData.returnTLLVs != NULL)
        {
            free(serverCtx->spcContainer.spcData.returnTLLVs);
            serverCtx->spcContainer.spcData.returnTLLVs = NULL;
        }
        
        if (serverCtx->spcContainer.spcData.p_version_supported.versions != NULL)
        {
            free(serverCtx->spcContainer.spcData.p_version_supported.versions);
            serverCtx->spcContainer.spcData.p_version_supported.versions = NULL;
        }
    }
}

//
//------------------------------------------------------------------------------
#if 0
#pragma mark -
#pragma mark Secure Key SKDDelivery Server Internal SPC functions
#endif
//------------------------------------------------------------------------------
//

static OSStatus SKDServerParseSPCContainer(
    const UInt8                *serverPlaybackCtx,
    UInt32                      serverPlaybackCtxSize,
    SKDServerSPCContainerV1 *spcContainer)
{
    OSStatus status = noErr;

    PS_RequireAction(serverPlaybackCtx     != NULL, return kDRMSKDServerParamErr;)
    PS_RequireAction(serverPlaybackCtxSize != 0   , return kDRMSKDServerParamErr;)
    PS_RequireAction(spcContainer          != NULL, return kDRMSKDServerParamErr;)
        
    // 2. parse spc container 
    // 2.1 parse the version 
    status = SKDServerReadBytes(&spcContainer->parser.currentOffset, PS_V1_VERSION_SZ, serverPlaybackCtx, serverPlaybackCtxSize, spcContainer->parser.scratch_4);
    
    if (PS_IS_NO_ERROR(status))
    {
        spcContainer->version = SKDServerGetBigEndian32(spcContainer->parser.scratch_4);
        PS_RequireAction( (spcContainer->version == 1), return kDRMSKDServerPlaybackContextVersionErr;)
        
        // 2.2 skip the 4 bytes reserved field
        status = SKDServerReadBytes(
                    &spcContainer->parser.currentOffset,
                    PS_V1_RESERVED_SZ, serverPlaybackCtx,
                    serverPlaybackCtxSize, spcContainer->parser.scratch_4);
        
        if (PS_IS_NO_ERROR(status))
        {        
            // 2.3 parse spc data iv  
            status = SKDServerReadBytes(
                        &spcContainer->parser.currentOffset,
                        PS_AES128_IV_SZ, serverPlaybackCtx,
                        serverPlaybackCtxSize, spcContainer->aesKeyIV);
            
            if (PS_IS_NO_ERROR(status))
            {        
                // 2.4 parse aes wrapped key
                status = SKDServerReadBytes(
                            &spcContainer->parser.currentOffset, 
                            PS_V1_WRAPPED_KEY_SZ, serverPlaybackCtx, 
                            serverPlaybackCtxSize, spcContainer->aesWrappedKey);
                
                if (PS_IS_NO_ERROR(status))
                {            
                    // 2.5 parse Certificate Hash
                    // This is where we should check the certificateHash and fail if it is not what is expected.
                    // Also, this is where the private RSA key would be selected if more than one was provisioned.
                    status = SKDServerReadBytes(
                                &spcContainer->parser.currentOffset, 
                                PS_V1_HASH_SZ, serverPlaybackCtx, 
                                serverPlaybackCtxSize, spcContainer->certificateHash);
     
                    if (PS_IS_NO_ERROR(status))
                    {
                        // 2.6 parse the SPC size
                        status = SKDServerReadBytes(
                                    &spcContainer->parser.currentOffset, 
                                    PS_V1_SPC_DATA_LENGTH_SZ, serverPlaybackCtx, 
                                    serverPlaybackCtxSize, spcContainer->parser.scratch_4);
                        
                        if (PS_IS_NO_ERROR(status))
                        {
                            spcContainer->spcDataOffset = spcContainer->parser.currentOffset;
                            spcContainer->spcDataSize = SKDServerGetBigEndian32(spcContainer->parser.scratch_4);
                            
                            PS_RequireAction(((spcContainer->spcDataSize + spcContainer->spcDataOffset) == serverPlaybackCtxSize), return kDRMSKDServerParserErr;)
                        }
                    }
                }
            }
        }
    }
                            
    return status;
}

static OSStatus SKDServerDecryptSPCData(
    const UInt8             *serverPlaybackCtx,
    UInt32                   serverPlaybackCtxSize,
    SKDServerSPCContainerV1 *spcContainer)
{
    OSStatus status = noErr;
    
    UInt8   localKey[PS_AES128_KEY_SZ];
    
    PS_RequireAction(serverPlaybackCtx     != NULL, return kDRMSKDServerParamErr;)
    PS_RequireAction(serverPlaybackCtxSize != 0   , return kDRMSKDServerParamErr;)
    PS_RequireAction(spcContainer          != NULL, return kDRMSKDServerParamErr;)
    
    // 2. allocate memory for decrypted spc data
    spcContainer->spcDecryptedData = calloc(1, spcContainer->spcDataSize);
    PS_RequireAction(spcContainer->spcDecryptedData != NULL, return kDRMSKDServerMemErr;)
    
    // 3. decrypt spc data
    // 3.1 Using the provisioned RSA private key, decrypt the RSA public encrypted AES key.
    //     This AES key is the one used to encrypt the SPC data (aka SPCK, Fig 2-2 of specification)
    status = SKDServerRSADecryptKey(spcContainer->aesWrappedKey, localKey);
     
    // 3.2 now decrypt the data
    if (PS_IS_NO_ERROR(status))
    {
        status = SKDServerAESEncryptDecrypt(
                    serverPlaybackCtx + spcContainer->spcDataOffset,
                    spcContainer->spcDecryptedData,
                    spcContainer->spcDataSize, localKey,
                    spcContainer->aesKeyIV,
                    kSKDServerAESDecrypt, kSKDServerAES_CBC);
    }
    
    return status;
}

static OSStatus SKDServerParseClientRefTime(
    SKDServerClientRefTime *refTime,
    SKDServerTLLV          *tllv)
{
    OSStatus status = noErr;
    
    PS_RequireAction(refTime != NULL, return kDRMSKDServerParamErr;)
    PS_RequireAction(   tllv != NULL, return kDRMSKDServerParamErr;)
    
    PS_RequireAction(tllv->valueData != NULL, return kDRMSKDServerParamErr;)
    PS_RequireAction(tllv->valueSize == PS_V1_CLI_REF_TIME_SZ, return kDRMSKDServerParamErr;)
    
    refTime->date = SKDServerGetBigEndian32(&tllv->valueData[0]);
    refTime->playback = SKDServerGetBigEndian32(&tllv->valueData[4]);
    refTime->playbackId = SKDServerGetBigEndian64(&tllv->valueData[8]);
    
    return status;
}

static OSStatus SKDServerParseSyncRental(
    SKDServerSPCDataV1      *spcData,
    SKDServerTLLV           *tllv)
{
    OSStatus    status = noErr;
    UInt32      tllvVersion = 0;
    UInt32      durationToRentalExpiry = 0;
    UInt8       offlineContentId[ PS_TLLV_OFFLINEKEY_CONTENTID_SZ ];

    PS_RequireAction( spcData != NULL, return kDRMSKDServerParamErr;)
    PS_RequireAction( tllv != NULL, return kDRMSKDServerParamErr;)
    PS_RequireAction( tllv->valueData != NULL, return kDRMSKDServerParamErr;)
    
    // Important: the TLLV is invalid when version is set to 0
    tllvVersion = SKDServerGetBigEndian32(&tllv->valueData[0]);
    if( tllvVersion != 0 )
    {
        memcpy( offlineContentId, &tllv->valueData[8], PS_TLLV_OFFLINEKEY_CONTENTID_SZ );
        durationToRentalExpiry = SKDServerGetBigEndian32(&tllv->valueData[24]);
        
        /* ADAPT:
        Server may record remaining playback duration time for the provided content ID.
        Value "0" means that the key is expired on the client side.
        Value "0xFFFFFFFF" means that content does not have expiry time associated 
        with the provided content ID.
        */
    }
    return status;
    
}

static OSStatus SKDServerParseSPCData(
    UInt8              *spcDataPtr,
    UInt32              spcDataSize,
    SKDServerSPCDataV1 *spcData)
{
    OSStatus status        = noErr;

    SKDServerTLLV  returnRequest = {0}, currentTLLV = {0};
    UInt64            tagValue      = 0;
    
    PS_RequireAction(spcData     != NULL, return kDRMSKDServerParamErr;)
    PS_RequireAction(spcDataPtr  != NULL, return kDRMSKDServerParamErr;)
    PS_RequireAction(spcDataSize != 0,    return kDRMSKDServerParamErr;)
    
    // the min size for a tag is 16 bytes (PS_TLLV_HEADER_SZ)
    // get the upper bound number of tags in the spc data and
    // allocate memory for it (assuming worst case of all empty tags)
    spcData->spcDataParser.TLLVs = calloc(spcDataSize/PS_TLLV_HEADER_SZ, sizeof(SKDServerTLLV));
    PS_RequireAction(spcData->spcDataParser.TLLVs != NULL, return kDRMSKDServerMemErr;)
        
    // 2. parse the different TLLVs    
    while ((spcData->spcDataParser.parser.currentOffset < spcDataSize) && (PS_IS_NO_ERROR(status)))
    {
        // 2.1 parse the TLLV tag (this moves the parser past the 8 byte tag on success)
        status = SKDServerReadBytes(
                    &spcData->spcDataParser.parser.currentOffset, 
                    PS_TLLV_TAG_SZ, spcDataPtr, 
                    spcDataSize, spcData->spcDataParser.parser.scratch_8);

        if (PS_IS_NO_ERROR(status))
        {
            tagValue = SKDServerGetBigEndian64(spcData->spcDataParser.parser.scratch_8);
                            
            // 2.2 parse L1 and L2 size of the current TLLV (this moves the parser to the next TLLV on success)
            status = SKDServerParseTLLV(
                        &spcData->spcDataParser, 
                        spcDataPtr, spcDataSize);
                
            if (PS_IS_NO_ERROR(status))
            {
                currentTLLV = spcData->spcDataParser.TLLVs[spcData->spcDataParser.nbTLLVs - 1];
                
                switch (tagValue) 
                {
                    case kSKDServerTagSessionKey_R1:
                    {
                        if ((spcData->spcDataParser.presenceFlags & FLAG_TAG_SK_R1) != 0)
                        {
                            PS_SET_ERROR_STATUS(status, kDRMSKDServerDupTagErr);
                        }
                        else
                        { 
                            PS_RequireAction(
                                (currentTLLV.valueSize == PS_V1_SKR1_SZ), 
                                return kDRMSKDServerParserErr;)
                            
                            status = SKDServerReadBytes(
                                        NULL, currentTLLV.valueSize, 
                                        currentTLLV.valueData, 
                                        currentTLLV.valueSize, spcData->sk_r1);
                                        
                            spcData->spcDataParser.presenceFlags |= FLAG_TAG_SK_R1;
                        }
                        break;
                    }
                    
                    case kSKDServerTagAntiReplaySeed:
                    {
                        if ((spcData->spcDataParser.presenceFlags & FLAG_TAG_AR) != 0)
                        {
                            PS_SET_ERROR_STATUS(status, kDRMSKDServerDupTagErr);
                        }
                        else 
                        {
                            PS_RequireAction(
                                (currentTLLV.valueSize == PS_AES128_KEY_SZ), 
                                return kDRMSKDServerParserErr;)
                                
                            status = SKDServerReadBytes(
                                        NULL, currentTLLV.valueSize, 
                                        currentTLLV.valueData, 
                                        currentTLLV.valueSize, spcData->antiReplaySeed);
                                                                                  
                            spcData->spcDataParser.presenceFlags |= FLAG_TAG_AR;
                        }
                        break;
                    }

                    case kSKDServerTagR2:
                    {
                        if ((spcData->spcDataParser.presenceFlags & FLAG_TAG_R2) != 0)
                        {
                            PS_SET_ERROR_STATUS(status, kDRMSKDServerDupTagErr);
                        }
                        else 
                        {
                            PS_RequireAction(
                                (currentTLLV.valueSize == PS_V1_R2_SZ), 
                                return kDRMSKDServerParserErr;)
                                
                            status = SKDServerReadBytes(
                                        NULL, currentTLLV.valueSize, 
                                        currentTLLV.valueData, 
                                        currentTLLV.valueSize, spcData->r2);
                                                                                 
                            spcData->spcDataParser.presenceFlags |= FLAG_TAG_R2;
                        }
                        break;
                    }

                    case kSKDServerTagSessionKey_R1_integrity:
                    {
                        if ((spcData->spcDataParser.presenceFlags & FLAG_TAG_SK_R1_INTEG) != 0)
                        {
                            PS_SET_ERROR_STATUS(status, kDRMSKDServerDupTagErr);
                        }
                        else 
                        {
                            PS_RequireAction(
                                (currentTLLV.valueSize == PS_V1_SKR1_INTEGRITY_SZ), 
                                return kDRMSKDServerParserErr;)
                                
                            status = SKDServerReadBytes(
                                        NULL, currentTLLV.valueSize, 
                                        currentTLLV.valueData, 
                                        currentTLLV.valueSize, spcData->sk_r1_integrity_tag);
                                        
                            spcData->spcDataParser.presenceFlags |= FLAG_TAG_SK_R1_INTEG;
                        }
                        break;
                    }
                                            
                    case kSKDServerTagAssetID:
                    {
                        if ((spcData->spcDataParser.presenceFlags & FLAG_TAG_ASSET_ID) != 0)
                        {
                            PS_SET_ERROR_STATUS(status, kDRMSKDServerDupTagErr);
                        }
                        else 
                        {
                            PS_RequireAction(
                                (currentTLLV.valueSize <= PS_V1_ASSET_ID_MAX_SZ), 
                                return kDRMSKDServerParserErr;)
                                
                            PS_RequireAction(
                                (currentTLLV.valueSize >= PS_V1_ASSET_ID_MIN_SZ), 
                                return kDRMSKDServerParserErr;)
                                                        
                            spcData->spcDataParser.presenceFlags |= FLAG_TAG_ASSET_ID;
                        }
                        break;
                    }
                    
                    case kSKDServerTagTransactionID:
                    {
                        if ((spcData->spcDataParser.presenceFlags & FLAG_TAG_TRANS_ID) != 0)
                        {
                            PS_SET_ERROR_STATUS(status, kDRMSKDServerDupTagErr);
                        }
                        else 
                        {
                            PS_RequireAction(
                                (currentTLLV.valueSize == PS_V1_TRANSACTION_ID_SZ), 
                                return kDRMSKDServerParserErr;)
                            
                            spcData->spcDataParser.presenceFlags |= FLAG_TAG_TRANS_ID;
                        }
                        break;
                    }
                    
                    case kSKDServerTagProtocolVersionUsed:
                    {
                        if ((spcData->spcDataParser.presenceFlags & FLAG_TAG_PROT_V_USED) != 0)
                        {
                            PS_SET_ERROR_STATUS(status, kDRMSKDServerDupTagErr);
                        }
                        else 
                        {
                            PS_RequireAction(
                                (currentTLLV.valueSize == PS_V1_PROTOCOL_VERSION_USED_SZ), 
                                return kDRMSKDServerParserErr;)
                            
                            spcData->p_version_used = SKDServerGetBigEndian32(currentTLLV.valueData);
                            
                            spcData->spcDataParser.presenceFlags |= FLAG_TAG_PROT_V_USED;
                        }
                        break;
                    }
                    
                    case kSKDServerTagProtocolVersionsSupported:
                    {
                        if ((spcData->spcDataParser.presenceFlags & FLAG_TAG_PROT_V_SUPPORTED) != 0)
                        {
                            PS_SET_ERROR_STATUS(status, kDRMSKDServerDupTagErr);
                        }
                        else 
                        {
                            PS_RequireAction(
                                (currentTLLV.valueSize % PS_V1_VERSION_SZ == 0), 
                                return kDRMSKDServerParserErr;)
                            
                            status = SKDServerParseSupportedVersions(
                                        &spcData->p_version_supported, 
                                        &currentTLLV);
                            
                            spcData->spcDataParser.presenceFlags |= FLAG_TAG_PROT_V_SUPPORTED;
                        }
                        break;
                    }
                    
                    case kSKDServerTagReturnRequest:
                    {
                        if ((spcData->spcDataParser.presenceFlags & FLAG_TAG_RET_REQ) != 0)
                        {
                            PS_SET_ERROR_STATUS(status, kDRMSKDServerDupTagErr);
                        }
                        else 
                        {
                            PS_RequireAction(
                                (currentTLLV.valueSize % PS_TLLV_TAG_SZ == 0), 
                                return kDRMSKDServerParserErr;)
                                
                            returnRequest.totalSize = currentTLLV.totalSize;
                            returnRequest.valueSize = currentTLLV.valueSize;
                            returnRequest.valueData = currentTLLV.valueData;
                            
                            spcData->spcDataParser.presenceFlags |= FLAG_TAG_RET_REQ;
                        }
                        break;
                    }
                    
                    case kSKDServerClientReferenceTimeTag:
                    {
                        if ((spcData->spcDataParser.presenceFlags & FLAG_TAG_CLIENT_REF_TIME) != 0)
                        {
                            PS_SET_ERROR_STATUS(status, kDRMSKDServerDupTagErr);
                        }
                        else
                        {
                            PS_RequireAction(
                                             ((currentTLLV.valueSize % (PS_V1_CLI_REF_TIME_SZ)) == 0),
                                             return kDRMSKDServerParserErr;)
                            
                            status = SKDServerParseClientRefTime(&spcData->playInfo, &currentTLLV);
                            
                            spcData->spcDataParser.presenceFlags |= FLAG_TAG_CLIENT_REF_TIME;
                        }
                        break;
                    }
                        
                    case kSKDServerStreamingIndicatorTag:
                    {
                        if ((spcData->spcDataParser.presenceFlags & FLAG_TAG_STREAMINGREQUIRED) != 0)
                        {
                            PS_SET_ERROR_STATUS(status, kDRMSKDServerDupTagErr);
                        }
                        else
                        {
                            UInt64 streamingRequired = 0;
                            
                            PS_RequireAction(
                                             (currentTLLV.valueSize % PS_V1_STREAMING_REQUIRED_SZ == 0),
                                             return kDRMSKDServerParserErr;)
                            
                            // read payload value
                            streamingRequired = SKDServerGetBigEndian64(currentTLLV.valueData);
                            switch( streamingRequired )
                            {
                                case kLSKDStreamingIndicatorAirPlay:
                                {
                                    // the content will be sent via AirPlay to AppleTV
                                    break;
                                }
                                case kLSKDStreamingIndicatorAVAdapter:
                                {
                                    // the content will be sent via Apple Digital AV Adapter
                                    break;
                                }
                                default:
                                {
                                    // playback will occur on the requesting device
                                    break;
                                }
                            }
                        }
                        break;
                    }
                    
                    case kSKDSServerOfflineSyncTag:
                    {
                        if ((spcData->spcDataParser.presenceFlags & FLAG_TAG_SYNC_RENTAL) != 0)
                        {
                            PS_SET_ERROR_STATUS(status, kDRMSKDServerDupTagErr);
                        }
                        else
                        {
                            status = SKDServerParseSyncRental(spcData, &currentTLLV);
                            
                            spcData->spcDataParser.presenceFlags |= FLAG_TAG_SYNC_RENTAL;
                        }
                        break;
                    }

                    default:
                    {
                        break;
                    }
                }
            }
        }
    }

     
    if (PS_IS_NO_ERROR(status))
    {
        // 3. enforce the minimum set of required TLLVs in V1
        if ((spcData->spcDataParser.presenceFlags & FLAG_SPC_REQUIRED_TAGS_V1) != FLAG_SPC_REQUIRED_TAGS_V1)
        {
            PS_SET_ERROR_STATUS(status, kDRMSKDServerMissingRequiredTag);
        }
        else
        {
            // 4. now that we have all the TLLVs, extract the ones specified by the return request tag
            status = SKDServerExtractReturnTags(&returnRequest, spcData);
        }
    }
                                    
    return status;
}

static OSStatus SKDServerProcessEncrypted_SK_R1(
    SKDServerSPCDataV1  *spcData)
{
    OSStatus status = noErr;
    
    // sanity check inputs
    PS_RequireAction(spcData != NULL, return kDRMSKDServerParamErr;)
    
    // 1. compute DAS_k and decrypt [SK..R1]
    // 1.1 compute DAS_k using the server derivation function
    UInt8 ASK[PS_AES128_KEY_SZ];
    
    status = SKDServerGetASK(ASK);
    
    if (PS_IS_NO_ERROR(status))
    {
        status = DFunction(spcData->r2, PS_V1_R2_SZ, ASK, spcData->DAS_k);

        if (PS_IS_NO_ERROR(status))
        {
            // 1.2 decrypt [SK...R1] using DAS_k
            status = SKDServerDecryptSK_R1(spcData);
            
            if (PS_IS_NO_ERROR(status))
            {
                SInt32 ret = 0;
                
                // 1.3 verify [SK...R1] integrity
                // this is part of the good practices per the specification
                ret = memcmp(spcData->sk_r1_integrity_tag, spcData->sk_r1_integrity, PS_V1_SKR1_INTEGRITY_SZ);
                PS_RequireAction(ret == 0, status = kDRMSKDServerIntegrityErr;)
            }
        }
    }
            
    return status;
}

static OSStatus SKDServerParseSPCV1(
    const UInt8             *serverPlaybackCtx,
    UInt32                   serverPlaybackCtxSize,
    SKDServerSPCContainerV1 *spcContainer)
{
    OSStatus status = noErr;
    
    PS_RequireAction(spcContainer != NULL, return kDRMSKDServerParamErr;)

    // 2. parse SPC container
    status = SKDServerParseSPCContainer(serverPlaybackCtx, serverPlaybackCtxSize, spcContainer);
    
    if (PS_IS_NO_ERROR(status))
    {
        // 3. open SPC Data
        status = SKDServerDecryptSPCData(serverPlaybackCtx, serverPlaybackCtxSize, spcContainer);
        
        if (PS_IS_NO_ERROR(status))
        {
            // 4. parse SPC data
            status = SKDServerParseSPCData(
                        spcContainer->spcDecryptedData, 
                        spcContainer->spcDataSize, &spcContainer->spcData);

            // 5. Version checking best practice
            if (PS_IS_NO_ERROR(status))
            {
                status = SKDServerCheckUsedVersion(&spcContainer->spcData);
                
                if (PS_IS_NO_ERROR(status))
                {
                    // 6. process [SK..R1]
                    status = SKDServerProcessEncrypted_SK_R1(&spcContainer->spcData);
                }
            }
        }
    }

    if(PS_IS_NO_ERROR(status))
    {
        SKDServerDumpSPCContainer(spcContainer);
    }
    
    return status;
}

//
//------------------------------------------------------------------------------
#if 0
#pragma mark -
#pragma mark Secure Key Delivery Server Internal CKC functions
#endif
//------------------------------------------------------------------------------
//

static OSStatus SKDServerSerializeCKCContainer(
    SKDServerCKCContainerV1  *ckcContainer, 
    UInt8                       **contentKeyCtx,
    UInt32                      *contentKeyCtxSize)
{
    OSStatus status = noErr;
    
    UInt8    *localckc     = NULL;
    UInt32    localckcSize = 0;
    
    PS_RequireAction(ckcContainer      != NULL, return kDRMSKDServerParamErr;)
    PS_RequireAction(contentKeyCtx     != NULL, return kDRMSKDServerParamErr;)
    PS_RequireAction(contentKeyCtxSize != NULL, return kDRMSKDServerParamErr;)  
    
    // 2. compute total ckc size & allocate
    localckcSize += PS_V1_VERSION_SZ /* version bytes */ + PS_V1_RESERVED_SZ /* reserved bytes */ +
                    PS_AES128_IV_SZ /* IV bytes */ +
                    PS_V1_CKC_DATA_LENGTH_SZ /* CKC data size bytes */ +
                    ckcContainer->ckcDataSize;
    
    localckc = calloc(1, localckcSize);
    PS_RequireAction(localckc != NULL, return kDRMSKDServerMemErr;)
    
    // 3. serialize version
    SKDServerSetBigEndian32(ckcContainer->version, localckc);
    ckcContainer->parser.currentOffset += PS_V1_VERSION_SZ;
    
    // 4. serialize reserved bytes
    SKDServerSetBigEndian32(0, localckc + ckcContainer->parser.currentOffset);
    ckcContainer->parser.currentOffset += PS_V1_RESERVED_SZ;
    
    // 5. serialize iv
    status = SKDServerWriteBytes(
                &ckcContainer->parser.currentOffset, PS_AES128_IV_SZ, 
                ckcContainer->aesKeyIV, localckcSize, localckc);
    
    if (PS_IS_NO_ERROR(status))
    {
        // 6. serialize ckc data size
        SKDServerSetBigEndian32(
            ckcContainer->ckcDataSize, localckc + ckcContainer->parser.currentOffset);
            
        ckcContainer->parser.currentOffset += PS_V1_CKC_DATA_LENGTH_SZ;
        
        // 7. copy the ckc data
        status = SKDServerWriteBytes(
                    &ckcContainer->parser.currentOffset, ckcContainer->ckcDataSize, 
                    ckcContainer->ckcDataPtr, localckcSize, localckc);
    }
    
    // clean up if error occured
    if (PS_IS_NO_ERROR(status))
    {
        *contentKeyCtx     = localckc;
        *contentKeyCtxSize = localckcSize;
    }
    else
    {
        if (localckc != NULL)
        {
            free(localckc);
            localckc = NULL;
        }
    }
        
    return status;
}

static OSStatus SKDServerEncryptCKCData(
    SKDServerCKCContainerV1 *ckcContainer,
    UInt8                   *key)
{
    OSStatus status = noErr;
    
    UInt8   aesIV[PS_AES128_IV_SZ];
    
    PS_RequireAction(ckcContainer != NULL, return kDRMSKDServerParamErr;)
    PS_RequireAction(key          != NULL, return kDRMSKDServerParamErr;)
     
    SKDServerReadBytes(NULL, PS_AES128_IV_SZ, ckcContainer->aesKeyIV, PS_AES128_IV_SZ, aesIV);
 
    // 2. in-place encryption
    status = SKDServerAESEncryptDecrypt(
                ckcContainer->ckcDataPtr, ckcContainer->ckcDataPtr, 
                ckcContainer->ckcDataSize, key, aesIV, 
                kSKDServerAESEncrypt, kSKDServerAES_CBC);
                    
    return status;
}

static OSStatus SKDServerSerializeCKCData(
    const SKDServerSPCDataV1  *spcData,
    SKDServerCKCContainerV1   *ckcContainer)    

{
    OSStatus status = noErr;
    
    PS_RequireAction(ckcContainer != NULL, return kDRMSKDServerParamErr;)
    PS_RequireAction(spcData      != NULL, return kDRMSKDServerParamErr;)
        
    // allocate required size
    ckcContainer->ckcDataPtr = calloc(1, ckcContainer->ckcDataSize);
    PS_RequireAction(ckcContainer->ckcDataPtr != NULL, return kDRMSKDServerParamErr;)

    // construct and serialize TLLVs
    // construct and serialize CK
    status = SKDServerConstructAndSerializeTLLV(
                kSKDServerTagCK, ckcContainer, spcData);
    
    if (PS_IS_NO_ERROR(status))
    {
        // construct and serialize R1
        status = SKDServerConstructAndSerializeTLLV(
                    kSKDServerTagR1, ckcContainer, spcData);
    }
    
    if (PS_IS_NO_ERROR(status))
    {
        // construct and serialize key duration tags if lease/rental logic is required
        if (((spcData->spcDataParser.presenceFlags & FLAG_TAG_CLIENT_REF_TIME) != 0) &&
            (ckcContainer->ckcData.keyDuration.keyType != 0))
        {
            // IMPORTANT: only iOS 11.0 and higher clients support "Offline Key TLLV".
            // For older clients the server should continue using "Key Duration TLLV"
            
            if(( /* ADAPT: verify client iOS version >= 11.0*/ true ) &&
               ((ckcContainer->ckcData.keyDuration.keyType == kKeyTypePersistence) || (ckcContainer->ckcData.keyDuration.keyType == kKeyTypePersistenceAndDuration)) )
            {
                status = SKDServerConstructAndSerializeTLLV( kSKDServerOfflineKeyTag, ckcContainer, spcData );
            }
            else
            {
                status = SKDServerConstructAndSerializeTLLV( kSKDServerKeyDurationTag, ckcContainer, spcData );
            }
        }
    }
    
    if (PS_IS_NO_ERROR(status))
    {
        // construct and serialize return tags
        status = SKDServerConstructAndSerializeTLLV(
                    kSKDServerReturnTags, ckcContainer, spcData);
    }
    
    return status;
}


static OSStatus SKDServerSetLeaseRentalParameters(
    SKDServerCtxV1  *serverCtx)
{
    OSStatus status = noErr;
    SKDServerSPCDataV1  *spcData = NULL;
    SKDServerCKCDataV1  *ckcData = NULL;
    
    PS_RequireAction(serverCtx != NULL, return kDRMSKDServerParamErr;)
    
    spcData = &serverCtx->spcContainer.spcData;
    ckcData = &serverCtx->ckcContainer.ckcData;
    PS_RequireAction(ckcData != NULL, return kDRMSKDServerParamErr;)
    
    if ((spcData->spcDataParser.presenceFlags & FLAG_TAG_CLIENT_REF_TIME) != 0)
    {
        /*
         ADAPT:
         Set lease/rental/persistence parameters if required
         */
        if( serverCtx->persistence == true )
        {
            if( serverCtx->persistenceDuration != 0 )
            {
                ckcData->keyDuration.keyType = kKeyTypePersistenceAndDuration;
                ckcData->keyDuration.rentalDuration = serverCtx->persistenceDuration;
                ckcData->keyDuration.playbackDuration = serverCtx->playbackDuration;
                ckcData->keyDuration.leaseDuration = 0; // not applicable for persistence
            }
            else
            {
                ckcData->keyDuration.keyType = kKeyTypePersistence;
            }
        }
        else
        {
            // select key type
            if( serverCtx->leaseDuration != 0 )
                ckcData->keyDuration.keyType = kKeyTypeLease;
            else if( serverCtx->rentalDuration != 0 )
                ckcData->keyDuration.keyType = kKeyTypeDuration;
            
            ckcData->keyDuration.leaseDuration = serverCtx->leaseDuration;
            ckcData->keyDuration.rentalDuration = serverCtx->rentalDuration;
            ckcData->keyDuration.playbackDuration = 0;  // not applicable for streaming
        }
        ckcData->keyDuration.reserved = 0x86d34a3a; // spec required value
    }
    
    return status;
}


static OSStatus SKDServerFillCKCData(
    SKDServerCtxV1  *serverCtx)
{
    OSStatus status = noErr;
    SKDServerSPCDataV1  *spcData = NULL;
    SKDServerCKCDataV1  *ckcData = NULL;
    
    PS_RequireAction(serverCtx != NULL, return kDRMSKDServerParamErr;)
    
    spcData = &serverCtx->spcContainer.spcData;
    ckcData = &serverCtx->ckcContainer.ckcData;
    PS_RequireAction(spcData != NULL, return kDRMSKDServerParamErr;)
    PS_RequireAction(ckcData != NULL, return kDRMSKDServerParamErr;)
    
    // 2.1 fetch content key (simulated content DB lookup based on assedId)
    ckcData->tag_ck_TotalSize = PS_AES128_IV_SZ + PS_AES128_KEY_SZ;
    status = SKDServerFetchContentKeyAndIV(serverCtx->assetId, ckcData->ck, ckcData->iv);
    
    if(PS_IS_NO_ERROR(status))
    {
        #if PS_DEBUG
        SKDServerDumpBuf("Plain CK", ckcData->ck, PS_AES128_KEY_SZ);
        #endif // PS_DEBUG

        // 2.2 In place ECB encrypt the content key with the session key
        status = SKDServerAESEncryptDecrypt(
                    ckcData->ck, ckcData->ck,
                    PS_AES128_KEY_SZ, spcData->sk, NULL,
                    kSKDServerAESEncrypt, kSKDServerAES_ECB);

        if(PS_IS_NO_ERROR(status))
        {
            // 3. set r1
            ckcData->tag_r1_TotalSize = PS_V1_R1_SZ + PS_V1_R1_PADDING_SZ;
            status = SKDServerWriteBytes(
                        NULL, PS_V1_R1_SZ, 
                        spcData->r1, PS_V1_R1_SZ, ckcData->r1);
        }
    }
    
    return status;
}

static OSStatus SKDServerFillCKCContainer(
    const SKDServerSPCDataV1  *spcData, 
    SKDServerCKCContainerV1   *ckcContainer)
{
    OSStatus status = noErr;
    
    PS_RequireAction(spcData      != NULL, return kDRMSKDServerParamErr;)
    PS_RequireAction(ckcContainer != NULL, return kDRMSKDServerParamErr;)
    
    // 2. set the version
    ckcContainer->version = PS_V1_VERSION; // currently, only V1 is supported
    
    // 3. generate the CKC container IV
    SKDServerGenRandom16(ckcContainer->aesKeyIV);
    
    // 4. set ckc data size
    status = SKDServerComputeCKCSize(spcData, ckcContainer);
    
    return status;
}

static OSStatus SKDServerGenerateCKCV1(
    SKDServerCtxV1  *serverCtx,
    UInt8           **contentKeyCtx,
    UInt32          *contentKeyCtxSize)
{
    OSStatus status = noErr;
    UInt8  key[16];

    PS_RequireAction(serverCtx != NULL, return kDRMSKDServerParamErr;)

    // 1. set lease/rental/persistence parameters
    status = SKDServerSetLeaseRentalParameters( serverCtx );

    // 2. prepare the container
    if (PS_IS_NO_ERROR(status))
    {
        status = SKDServerFillCKCContainer(
                &serverCtx->spcContainer.spcData, &serverCtx->ckcContainer);
    }
    if (PS_IS_NO_ERROR(status))
    {
        // 3. prepare the ckc data
        status = SKDServerFillCKCData( serverCtx );
    }
    if (PS_IS_NO_ERROR(status))
    {
        // 4. serialize it
        status = SKDServerSerializeCKCData(
                    &serverCtx->spcContainer.spcData, &serverCtx->ckcContainer);
    }
    if (PS_IS_NO_ERROR(status))
    {
        // 5.1 Derive encryption key from anti replay seed and R1
        status = SKDServerDeriveAntiReplayKey(serverCtx->spcContainer.spcData.antiReplaySeed, 
                            serverCtx->spcContainer.spcData.r1, PS_V1_R1_SZ, key);
    }
    if (PS_IS_NO_ERROR(status))
    {
        // 5.2 encrypt the ckc using the anti replay key 
        status = SKDServerEncryptCKCData(
                    &serverCtx->ckcContainer, key);
    }
    if (PS_IS_NO_ERROR(status))
    {
        // 6. serialize the ckc container
        status = SKDServerSerializeCKCContainer(
                    &serverCtx->ckcContainer, contentKeyCtx, contentKeyCtxSize);
    }
    
#if PS_DEBUG
    if (PS_IS_NO_ERROR(status))
    {
        SKDServerDumpBuf("***Dumping encrypted generated CKC:", *contentKeyCtx, *contentKeyCtxSize);
    }
#endif
    
    return  status;
}

static Boolean isPlayingValidContext(const SKDServerSPCDataV1  *spcData, Boolean *is_valid_tag)
{
    Boolean rc = true;
    
    *is_valid_tag = true;
    
    //check this condition only in case of the SPC with the playinfo TLLV present
    if ((spcData->spcDataParser.presenceFlags & FLAG_TAG_CLIENT_REF_TIME) != 0)
    {
        switch (spcData->playInfo.playback)
        {
            case kCurrentlyPlayingCKRequired:
            case kCurrentlyPlayingCKNotRequired:
            case kFirstPlaybackCKRequired:
                break;
                
            case kPlaybackSessionStopped:
                rc = false;
                break;
                
            default:
                rc = false;
                *is_valid_tag = false;
        }
    }
    
    return rc;
}

/* ADAPT */
// if needed set lease duration, rental duration, and whether persistence is allowed
static void SKDServerSetLeaseRentalPersistence( SKDServerCtxV1  *serverCtx )
{
    // streaming
    serverCtx->leaseDuration = 0;
    serverCtx->rentalDuration = 0;
    
    // persistence
    serverCtx->persistence = false;
    
    // how much time user has to start the playback after acquiring the key (in seconds).
    // "0" means storage expiration should not be enforced by the client
    // Example: serverCtx->persistenceDuration = 2592000; // 30 days
    serverCtx->persistenceDuration = 0;
    
    // how much time user has to complete watching after first playback started (in seconds).
    // "0" means playback expiration should not be enforced by the client
    // Example: serverCtx->playbackDuration = 86400; // 24 hours
    // IMPORTANT: playbackDuration is only supported by clients running iOS 11.0 or later.
    //            It will not be enforced by older clients
    serverCtx->playbackDuration = 0;
}

//
//------------------------------------------------------------------------------
#if 0
#pragma mark -
#pragma mark Secure Key Delivery Server Public APIs
#endif
//------------------------------------------------------------------------------
//

OSStatus SKDServerGenCKC(
    const UInt8   *serverPlaybackCtx,
    UInt32         serverPlaybackCtxSize,
    const UInt8   *assetId,
    UInt8        **contentKeyCtx,
    UInt32        *contentKeyCtxSize)
{
    OSStatus status = noErr;
    Boolean is_tag_valid = true;
    UInt8    localVersion[PS_V1_VERSION_SZ] = {0};
    
    status = SKDServerReadBytes(NULL, PS_V1_VERSION_SZ, serverPlaybackCtx, serverPlaybackCtxSize, localVersion);
    
    if (PS_IS_NO_ERROR(status))
    {        
        switch (SKDServerGetBigEndian32(localVersion)) 
        {
            case kServerPlaybackCtxV1:
            {
                SKDServerCtxV1 serverCtx;

                memset(&serverCtx, 0, sizeof(SKDServerCtxV1));
                                
                // 1. parse SPC
                status = SKDServerParseSPCV1(serverPlaybackCtx, serverPlaybackCtxSize, &serverCtx.spcContainer);
                
                if (PS_IS_NO_ERROR(status))
                {
                    // set the incoming assetId in the ctx
                    serverCtx.assetId = assetId;

                    // set lease, rental durations and/or persistence if required for the asset
                    SKDServerSetLeaseRentalPersistence(&serverCtx);

                    // 2. generate ckc
                    if (isPlayingValidContext(&serverCtx.spcContainer.spcData, &is_tag_valid))
                    {
                        status =  SKDServerGenerateCKCV1(&serverCtx, contentKeyCtx, contentKeyCtxSize);
                    }
                    else
                    {
                    	if (!is_tag_valid)
                    	{
                        	PS_SET_ERROR_STATUS(status, kDRMSKDServerCKCGenErr);
                    	}
                    }
                }
                
                SKDServerDestroyCtx(&serverCtx);
                break;
            }
            
            default:
                PS_SET_ERROR_STATUS(status, kDRMSKDServerPlaybackContextVersionErr);
                break;
        }
    }
    
    return status;
}
   
OSStatus SKDServerDisposeStorage(
    void *p)
{
    OSStatus status = noErr;
    
    if (p != NULL)
    {
        free(p);
        p = NULL;
    }
    
    return status;
}

