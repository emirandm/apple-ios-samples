/*
Copyright (C) 2016 Apple Inc. All Rights Reserved.
 See the Apple Developer Program License Agreement for this file's licensing information.
 All use of these materials is subject to the terms of the Apple Developer Program License Agreement.
 
Abstract:
KSM reference implementation header file
*/
#ifndef SKD_SERVER_H_
#define SKD_SERVER_H_

//
//------------------------------------------------------------------------------
// Secure Key Delivery Server Defines
//------------------------------------------------------------------------------
//

// SPC v1 and CKC v1 field sizes as per specification for parsing
#define PS_V1_ASSET_ID_MIN_SZ              2
#define PS_V1_VERSION_SZ                   4
#define PS_V1_RESERVED_SZ                  4
#define PS_V1_SPC_DATA_LENGTH_SZ           4
#define PS_V1_CKC_DATA_LENGTH_SZ           4
#define PS_V1_PROTOCOL_VERSION_USED_SZ     4
#define PS_V1_TRANSACTION_ID_SZ            8
#define PS_V1_SKR1_INTEGRITY_SZ            16
#define PS_V1_CLI_REF_TIME_SZ              16
#define PS_V1_HASH_SZ                      20
#define PS_V1_R2_SZ                        21
#define PS_V1_R1_SZ                        44
#define PS_V1_R1_PADDING_SZ               (64-(PS_V1_R1_SZ))
#define PS_V1_SKR1_SZ                      112
#define PS_V1_WRAPPED_KEY_SZ               128 
#define PS_V1_ASSET_ID_MAX_SZ              200
#define PS_V1_STREAMING_REQUIRED_SZ        8

// TLLV sizes
#define PS_TLLV_TAG_SZ            8
#define PS_TLLV_TOTAL_LENGTH_SZ   4
#define PS_TLLV_VALUE_LENGTH_SZ   4
#define PS_TLLV_HEADER_SZ         ((PS_TLLV_TAG_SZ)+(PS_TLLV_TOTAL_LENGTH_SZ)+(PS_TLLV_VALUE_LENGTH_SZ))

#define PS_TLLV_DURATION_LEASE_SZ           4
#define PS_TLLV_DURATION_CK_SZ              4
#define PS_TLLV_DURATION_KEY_TYPE_SZ        4
#define PS_TLLV_DURATION_RESV_SZ            4
#define PS_TLLV_DURATION_VALUE_SZ           ((PS_TLLV_DURATION_LEASE_SZ)+(PS_TLLV_DURATION_CK_SZ)+(PS_TLLV_DURATION_KEY_TYPE_SZ)+(PS_TLLV_DURATION_RESV_SZ))
#define PS_TLLV_DURATION_PADDING_SZ         16

// offline key TLLV (0x6375d9727060218c)
#define PS_TLLV_OFFLINEKEY_VALUE_SZ         32
#define PS_TLLV_OFFLINEKEY_PADDING_SZ       16
#define PS_TLLV_OFFLINEKEY_TLLV_VERSION     1
#define PS_TLLV_OFFLINEKEY_CONTENTID_SZ     16

// Standard sizes
#define PS_AES128_KEY_SZ          16
#define PS_AES128_IV_SZ           16

// Other defines
#define PS_V1_VERSION             1

// Internal TLLV presence flags for SPC parsing
#define FLAG_TAG_SK_R1              0x00000001
#define FLAG_TAG_AR                 0x00000002
#define FLAG_TAG_R2                 0x00000004
#define FLAG_TAG_ASSET_ID           0x00000008
#define FLAG_TAG_TRANS_ID           0x00000010
#define FLAG_TAG_PROT_V_USED        0x00000020
#define FLAG_TAG_PROT_V_SUPPORTED   0x00000040
#define FLAG_TAG_RET_REQ            0x00000100
#define FLAG_TAG_SK_R1_INTEG        0x00000200
#define FLAG_TAG_CLIENT_REF_TIME    0x00000400
#define FLAG_TAG_STREAMINGREQUIRED  0x00000800
#define FLAG_TAG_SYNC_RENTAL        0x00001000

#define FLAG_SPC_REQUIRED_TAGS_V1   ( FLAG_TAG_SK_R1 | FLAG_TAG_AR | FLAG_TAG_R2 | \
                                      FLAG_TAG_ASSET_ID | FLAG_TAG_TRANS_ID | FLAG_TAG_PROT_V_USED | \
                                      FLAG_TAG_PROT_V_SUPPORTED | FLAG_TAG_RET_REQ | FLAG_TAG_SK_R1_INTEG )
    
//
//------------------------------------------------------------------------------
// Secure Key Delivery Server Constants
//------------------------------------------------------------------------------
//
enum {
    kDRMSKDServerPlaybackContextVersionErr = -42580,
    kDRMSKDServerParserErr                 = -42581,
    kDRMSKDServerCKCGenErr                 = -42582,
    kDRMSKDServerMissingRequiredTag        = -42583,
    kDRMSKDServerCKNotFound                = -42584,
    kDRMSKDServerParamErr                  = -42585,
    kDRMSKDServerMemErr                    = -42586,
    kDRMSKDServerFileNotFoundErr           = -42587,
    kDRMSKDServerOpenSSLErr                = -42588,
    kDRMSKDServerIntegrityErr              = -42589,
    kDRMSKDServerVersionErr                = -42590,
    kDRMSKDServerDupTagErr                 = -42591,
};


enum {
    kServerPlaybackCtxV1 = 1
};
    
typedef enum {
    kSKDServerTagR2                        = 0x71b5595ac1521133ULL,                  
    kSKDServerTagAntiReplaySeed            = 0x89c90f12204106b2ULL,                 
    kSKDServerTagSessionKey_R1             = 0x3d1a10b8bffac2ecULL,
    kSKDServerTagSessionKey_R1_integrity   = 0xb349d4809e910687ULL,          
    kSKDServerTagAssetID                   = 0x1bf7f53f5d5d5a1fULL,                    
    kSKDServerTagTransactionID             = 0x47aa7ad3440577deULL,              
    kSKDServerTagProtocolVersionUsed       = 0x5d81bcbcc7f61703ULL,        
    kSKDServerTagProtocolVersionsSupported = 0x67b8fb79ecce1a13ULL,  
    kSKDServerTagReturnRequest             = 0x19f9d4e5ab7609cbULL,
    kSKDServerTagCK                        = 0x58b38165af0e3d5aULL,
    kSKDServerTagR1                        = 0xea74c4645d5efee9ULL,
    kSKDServerReturnTags                                          ,
    kSKDServerClientReferenceTimeTag       = 0xeb8efdf2b25ab3a0ULL,
    kSKDServerKeyDurationTag               = 0x47acf6a418cd091aULL,
    kSKDServerOfflineKeyTag                = 0x6375d9727060218cULL,
    kSKDServerStreamingIndicatorTag        = 0xabb0256a31843974ULL,
    kSKDSServerOfflineSyncTag              = 0x77966de1dc1083adULL,
} SKDServerTagValue;
    
typedef enum {
    kLSKDStreamingIndicatorAirPlay         = 0xabb0256a31843974ULL,
    kLSKDStreamingIndicatorAVAdapter       = 0x5f9c8132b59f2fdeULL
} SKDStreamingIndicatorValue;

//
//------------------------------------------------------------------------------
// Secure Key Delivery Server Public APIs
//------------------------------------------------------------------------------
//
#ifdef  __cplusplus
extern "C" {
#endif

/*!
 * This function will compute the content key context returned to client by the SKDServer library.
 *
 * @param[in]       serverPlaybackCtx       incoming server playback context (SPC message)
 * @param[in]       serverPlaybackCtxSize   size of the above
 * @param[in]       assetID                 incoming assetId, for illustration purposes only, NULL terminated base64 string
 * @param[out]      contentKeyCtx           content key context (CKC message), to be disposed with SKDServerDisposeStorage()
 * @param[out]      contentKeyCtxSize       size of the above
 */
OSStatus SKDServerGenCKC(
    const UInt8   *serverPlaybackCtx,
    UInt32         serverPlaybackCtxSize,
    const UInt8   *assetId,
    UInt8        **contentKeyCtx,
    UInt32        *contentKeyCtxSize);

/*!
 * This function will dispose storage returned to client by the SKDServer library.
 * Used: by anyone who calls functions which return the arbitrary sized data
 *
 * @param[in]       p                       pointer to buffer to be disposed, may be NULL
 */
OSStatus SKDServerDisposeStorage(
    void *p);
#ifdef  __cplusplus
}
#endif
#endif // SKD_SERVER_H_
