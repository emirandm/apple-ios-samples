# FPS Client Sample Code

This directory contains the following sample code projects:

* FairPlay Streaming in Safari
    
    * This sample demonstrates how to create an FPS aware client on iOS or macOS using the HTML5 Encrypted Media Extensions (EME) support in Safari.

* HLS Catalog With FPS - AVContentKeySession:
    
    * This sample demonstrates how to create an FPS aware client application for iOS and tvOS using the `AVContentKeySession` APIs introduced as part of iOS 11.  It also demonstrates downloading HLS and FPS streams for offline playback using the `AVAggregateAssetDownloadTask` API.
    
    * The APIs in this sample are only available on: 
        * iOS 11 and later.
        * tvOS 11 and later.

* HLS Catalog With FPS - AVAssetResourceLoader:
    
    * This sample demonstrates how to create an FPS aware client application for iOS and tvOS using the `AVAssetResourceLoader` APIs.  It also demonstrates downloading HLS and FPS streams for offline playback using the `AVAssetDownloadTask` API.
    
    * The `AVAssetResourceLoader` APIs used in this sample for streaming only content key retrieval are available in iOS and tvOS 9.0 and later.  
        * The persistable content key related API calls are available in iOS 10.0 and later.
    * The `AVAssetDownloadTask` APIs are available only on iOS 10.0 and later.

