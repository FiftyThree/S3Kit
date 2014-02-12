//
//  NSData+MD5.m
//  NSData+MD5
//
//

#import "NSData+MD5.h"
#import "NSData+Base64.h"
#import <CommonCrypto/CommonHMAC.h>

@implementation NSData (MD5)

- (NSData *)md5SignatureData
{
    static const int kNumBytes = 16;
    unsigned char result[kNumBytes];
    CC_MD5([self bytes], (CC_LONG)[self length], result);
    return [NSData dataWithBytes:result length:sizeof(unsigned char) * kNumBytes];
}

- (NSString *)md5SignatureBase64
{
    return [[self md5SignatureData] base64EncodedString];
}

- (NSString *)md5SignatureBase16
{
    return [[self md5SignatureData] base16EncodedString];
}

@end

