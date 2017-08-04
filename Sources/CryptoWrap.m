//
//  CommonCrypto.m
//  JWT
//
//  Created by Alexander v. Below on 28.07.17.
//  Copyright © 2017 Cocode. All rights reserved.
//

#import "CryptoWrap.h"

@implementation CryptoWrap
+ (NSData *) CCHmacWithKey:(NSData *)key message:(NSData *) message algorithm:(CryptoWrapAlgorithm)algorithm;
 {
  CCHmac(kCCHmacAlgSHA224, NULL, 0, NULL, 0, NULL);
  return nil;
//  CCHmac(CCHmacAlgorithm(variant), keyBytes, key.count, dataBytes, messageData.count, signature)
}
@end
