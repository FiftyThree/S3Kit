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

- (NSData *)dataFromBase16String
{
    NSString *theString = [[self componentsSeparatedByCharactersInSet:
		[NSCharacterSet whitespaceAndNewlineCharacterSet]] componentsJoinedByString:nil];

    NSMutableData* data = [NSMutableData data];
    int idx;
    
	for (idx = 0; idx+2 <= theString.length; idx+=2)
	{
        NSRange range = NSMakeRange(idx, 2);
        NSString *hexStr = [theString substringWithRange:range];
        NSScanner *scanner = [NSScanner scannerWithString:hexStr];
        unsigned int intValue;
        if ([scanner scanHexInt:&intValue])
		{
            [data appendBytes:&intValue length:1];
		}
    }
	
    return data;
}

@end

