/*
Copyright (C) 2016 Apple Inc. All Rights Reserved.
 See the Apple Developer Program License Agreement for this file's licensing information.
 All use of these materials is subject to the terms of the Apple Developer Program License Agreement.
 
Abstract:
DFunction prototype
*/

#ifndef _SKDSERVER_D_H_
#define _SKDSERVER_D_H_

/* D as explained in the document */

#define R2_SIZE 16
OSStatus DFunction(
        UInt8  *R2,             /* in */
        UInt32  R2_sz,          /* in */
const   UInt8   ASk[16],        /* in */
        UInt8   DASk[16]        /* out */
        );

#endif // _SKDSERVER_D_H_
