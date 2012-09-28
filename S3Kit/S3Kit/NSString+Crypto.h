//
//  NSString+Crypto.h
//  NSString+Crypto
//
//

#import <Foundation/Foundation.h>

@interface NSString (Crypto)

- (NSData *)encryptWithKey:(NSString *)privateKey;

@end

