//
//  NSString+Crypto.h
//  NSString+Crypto
//
//

#import <Foundation/Foundation.h>

@interface NSString (Crypto)

- (NSData *)encryptWithKey:(NSString *)privateKey;
- (NSData *)dataFromBase16String;

@end

