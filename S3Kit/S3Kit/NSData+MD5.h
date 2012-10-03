//
//  NSData+MD5.h
//  NSData+MD5
//
//

#import <Foundation/Foundation.h>

@interface NSData (MD5)

- (NSData *)md5SignatureData;
- (NSString *)md5SignatureBase64;
- (NSString *)md5SignatureBase16;

@end

