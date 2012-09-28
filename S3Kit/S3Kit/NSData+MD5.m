//
//  NSData+MD5.m
//  NSData+MD5
//
//

#import "NSData+MD5.h"
#import "NSData+Base64.h"
#import <CommonCrypto/CommonHMAC.h>

@implementation NSData (MD5)

- (NSString *)md5Signature
{
    static const int kNumBytes = 16;
    unsigned char result[kNumBytes];
    CC_MD5([self bytes], [self length], result);
    return [[NSData dataWithBytes:result length:sizeof(unsigned char) * kNumBytes] base64EncodedString];
}

@end

