//
//  CommonCrypto.h
//  JWT
//
//  Created by Alexander v. Below on 28.07.17.
//  Copyright © 2017 Cocode. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCrypto.h>

typedef enum : NSUInteger {
  CryptoWrap256 = kCCHmacAlgSHA256,
  CryptoWrap384 = kCCHmacAlgSHA384,
  CryptoWrap512 = kCCHmacAlgSHA512
} CryptoWrapAlgorithm;

@interface CryptoWrap : NSObject
+ (NSData *) CCHmacWithKey:(NSData *)key message:(NSData *) message algorithm:(CryptoWrapAlgorithm)algorithm;
@end
