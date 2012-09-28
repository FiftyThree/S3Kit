//
//  NSString+Crypto.m
//  NSString+Crypto
//
//

#import "NSString+Crypto.h"
#import <CommonCrypto/CommonHMAC.h>

@implementation NSString (Crypto)

- (NSData *)encryptWithKey:(NSString *)privateKey
{
    // encode the string and the private key as NSData
    NSData *clearTextData = [self dataUsingEncoding:NSUTF8StringEncoding];
    NSData *privateKeyData = [privateKey dataUsingEncoding:NSUTF8StringEncoding];

    uint8_t digest[CC_SHA1_DIGEST_LENGTH] = {0};
    // create a crypto context and apply hmac algorithm
    CCHmacContext hmacContext;
    CCHmacInit(&hmacContext, kCCHmacAlgSHA1, privateKeyData.bytes, privateKeyData.length);
    CCHmacUpdate(&hmacContext, clearTextData.bytes, clearTextData.length);
    CCHmacFinal(&hmacContext, digest);

    // convert the encrypted bytes back into a NS data object
    NSData *encryptedData = [NSData dataWithBytes:digest length:CC_SHA1_DIGEST_LENGTH];

    return encryptedData;
}
@end

