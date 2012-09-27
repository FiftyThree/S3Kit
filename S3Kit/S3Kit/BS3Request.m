//
//  BS3Request.m
//  BS3Request
//
//  Created by Brandon Smith on 7/15/12.
//  Copyright (c) 2012 TokenGnome. All rights reserved.
//

#import "BS3Request.h"
#import "NSData+Base64.h"
#import <CommonCrypto/CommonHMAC.h>

@interface BS3Request ()

@property (nonatomic, copy) NSString *bucketName;
@property (nonatomic, copy) NSString *resourcePath;

@property (nonatomic, copy) NSString *accessKey;
@property (nonatomic, copy) NSString *secretKey;

@end

@implementation BS3Request

+ (NSString *)urlEncodedParameter:(NSString *)parameterValue
{
    return [[parameterValue stringByAddingPercentEscapesUsingEncoding:NSUTF8StringEncoding]
            stringByReplacingOccurrencesOfString:@"+" withString:@"%2B"];
}

+ (NSString *)dateHeaderForDate:(NSDate *)date
{
    static NSDateFormatter *df = nil;
    if (!df)
    {
        static dispatch_once_t oncePredicate;
        dispatch_once(&oncePredicate, ^{
            df = [[NSDateFormatter alloc] init];
            df.locale = [[NSLocale alloc] initWithLocaleIdentifier:@"en_US"];
            df.timeZone = [NSTimeZone timeZoneWithAbbreviation:@"GMT"];
            df.dateFormat = @"EEE',' dd MMM yyyy HH':'mm':'ss '+0000'";
        });
    }
    return [df stringFromDate:date];
}

+ (NSString *)authorizationHeaderForString:(NSString *)stringToSign
                                 accessKey:(NSString *)accessKey
                                 secretKey:(NSString *)secretKey
{
    NSData *encryptedStringData = [BS3Request encrypt:stringToSign withKey:secretKey];
    NSString *authToken = [encryptedStringData base64EncodedString];
    return [NSString stringWithFormat:@"AWS %@:%@", accessKey, authToken];
}

+ (NSData *)encrypt:(NSString *)string withKey:(NSString *)privateKey
{
    // encode the string and the private key as NSData
    NSData *clearTextData = [string dataUsingEncoding:NSUTF8StringEncoding];
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

+ (NSString *)base64EncodedStringWithData:(NSData *)dataToEncode
{
    return nil;
}

+ (NSString *)md5SignatureForData:(NSData *)data
{
    static const int kNumBytes = 16;
    unsigned char result[kNumBytes];
    CC_MD5(data.bytes, data.length, result);
    return [[NSData dataWithBytes:result length:sizeof(unsigned char) * kNumBytes] base64EncodedString];
}

+ (NSString *)stringForParameters:(NSDictionary *)parameters
{
    if (!parameters || [[parameters allKeys] count] < 1) return @"";
    static NSSet *validParameters;
    if (!validParameters) validParameters = [NSSet setWithObjects:@"delimiter",
                                             @"marker",
                                             @"max-keys",
                                             @"prefix", nil];
    NSString *paramStr = @"";
    for (NSString *key in [parameters allKeys])
    {
        paramStr = [validParameters containsObject:key] ?
        [paramStr stringByAppendingFormat:@"&%@=%@",
         key,
         [BS3Request urlEncodedParameter:[parameters objectForKey:key]]] :
        paramStr;
    }
    NSLog(@"%@", paramStr);

    return ([paramStr isEqualToString:@""] ?
            @"" :
            [paramStr stringByReplacingCharactersInRange:NSMakeRange(0, 1) withString:@""]);
}

+ (NSString *)URLStringForBucket:(NSString *)bucketName
                    resourcePath:(NSString *)resourcePath
                          params:(NSDictionary *)params {

    NSString *urlString = [NSString stringWithFormat:@"https://s3.amazonaws.com/%@%@",
                           bucketName,
                           resourcePath];

    NSString *parameterString = [BS3Request stringForParameters:params];
    if (parameterString.length > 0)
    {
        urlString = [urlString stringByAppendingFormat:@"?%@", parameterString];
    }

    return urlString;
}

- (id)initWithBucketName:(NSString *)bucketName
            resourcePath:(NSString *)resourcePath
              parameters:(NSDictionary *)params
               accessKey:(NSString *)accessKey
               secretKey:(NSString *)secretKey {

    NSString *URLString = [BS3Request URLStringForBucket:bucketName
                                            resourcePath:resourcePath
                                                  params:params];

    self = [super initWithURL:[NSURL URLWithString:URLString]];
    if (self)
    {
        self.bucketName = bucketName;
        self.resourcePath = resourcePath;

        self.accessKey = accessKey;
        self.secretKey = secretKey;


    }

    return self;
}

- (NSString *)dateHeader
{
    return [BS3Request dateHeaderForDate:[NSDate date]];
}

- (NSString *)stringToSign
{
    NSString *contentMd5 = [self.allHTTPHeaderFields objectForKey:@"Content-Md5"];
    NSString *contentType = [self.allHTTPHeaderFields objectForKey:@"Content-Type"];
    NSString *date = [self.allHTTPHeaderFields objectForKey:@"Date"];

    NSString *result = [NSString stringWithFormat:@""
                        @"%@\n" // HTTP Method
                        @"%@\n" // Content MD5
                        @"%@\n" // Content type
                        @"%@\n" // Date
                        @"%@"   // Amazon Canonicalized Headers
                        @"%@",  // Amazon Canonicalized Resource
                        self.HTTPMethod,
                        contentMd5 ? contentMd5 : @"",
                        contentType ? contentType : @"",
                        date,
                        @"",
                        [NSString stringWithFormat:@"/%@%@", self.bucketName, self.resourcePath]];

    return result;
}

- (void)setAuthorizationHeader
{
    if (self.HTTPBody)
    {
        [self setValue:[BS3Request md5SignatureForData:self.HTTPBody] forHTTPHeaderField:@"Content-Md5"];
    }

    [self setValue:[self dateHeader] forHTTPHeaderField:@"Date"];

    [self setValue:[self authorizationHeader] forHTTPHeaderField:@"Authorization"];
}

- (NSString *)authorizationHeader
{
    return [BS3Request authorizationHeaderForString:self.stringToSign
                                          accessKey:self.accessKey
                                          secretKey:self.secretKey];
}

@end
