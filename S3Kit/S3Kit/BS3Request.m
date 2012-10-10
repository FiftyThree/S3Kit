//
//  BS3Request.m
//  BS3Request
//
//

#import "BS3Request.h"
#import "NSData+Base64.h"
#import "NSData+MD5.h"
#import <CommonCrypto/CommonHMAC.h>
#import "NSString+Crypto.h"

@interface NSString (URL)
- (NSString *)urlEncoded;
@end

@implementation NSString (URL)

- (NSString *)urlEncoded
{
    NSString *result =  [self stringByAddingPercentEscapesUsingEncoding:NSASCIIStringEncoding]; // doesn't cover much
	
	result = [[result stringByAddingPercentEscapesUsingEncoding:NSUTF8StringEncoding]
            stringByReplacingOccurrencesOfString:@"+" withString:@"%2B"];
			
	result =  [[result stringByAddingPercentEscapesUsingEncoding:NSUTF8StringEncoding]
            stringByReplacingOccurrencesOfString:@"/" withString:@"%2F"];
			
	return result;

    //return [self stringByAddingPercentEscapesUsingEncoding:NSASCIIStringEncoding];
}

@end

@implementation BS3Request

- (id)init
{
	self = [super init];
	self.parameters = [NSMutableDictionary dictionary];
	self.HTTPMethod = @"GET";
	self.date = [NSDate date];
    [self addValue:[self dateHeader] forHTTPHeaderField:@"Date"];
	self.usesSSL = YES;


	return self;
}

//#warning this url encoding doesn't look right

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


- (NSString *)stringForParameters
{
    if (!self.parameters || [[self.parameters allKeys] count] < 1) return @"";
    static NSSet *validParameters;
    if (!validParameters)
	{
		validParameters = [NSSet setWithObjects:@"delimiter",
                                             @"marker",
                                             @"max-keys",
                                             @"delimiter",
                                             @"prefix", nil];
	}
	
    NSString *paramStr = @"";
    for (NSString *key in [self.parameters allKeys])
    {
        paramStr = [validParameters containsObject:key] ?
        [paramStr stringByAppendingFormat:@"&%@=%@", key, [[self.parameters objectForKey:key] urlEncoded]] :
        paramStr;
    }
	
    //NSLog(@"%@", paramStr);

    return ([paramStr isEqualToString:@""] ?
            @"" :
            [paramStr stringByReplacingCharactersInRange:NSMakeRange(0, 1) withString:@""]);
}

- (NSString *)composedURLString
{
	NSString *scheme = self.usesSSL ? @"https" : @"http";
	NSString *urlString;

	if(self.redirectUrlString)
	{
		urlString = [self.redirectUrlString stringByAppendingString:self.resourcePath];
	}
	else
	{
		//urlString = [NSString stringWithFormat:@"%@://s3.amazonaws.com/%@%@",
		//	scheme, bucketName, resourcePath];

		urlString = [NSString stringWithFormat:@"%@://%@.s3.amazonaws.com%@",
							scheme, self.bucketName, self.resourcePath];
	}
					
	NSString *parameterString = [self stringForParameters];
	
	if (parameterString.length > 0)
	{
		urlString = [urlString stringByAppendingFormat:@"?%@", parameterString];
	}
	
    return urlString;
}


- (NSString *)dateHeader
{
    return [BS3Request dateHeaderForDate:self.date];
}

- (NSString *)stringToSign
{
    NSString *contentMd5  = [self.allHTTPHeaderFields objectForKey:@"Content-Md5"];
    NSString *contentType = [self.allHTTPHeaderFields objectForKey:@"Content-Type"];
    NSString *dateString  = [self.allHTTPHeaderFields objectForKey:@"Date"];

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
                        dateString,
                        @"",
                        [NSString stringWithFormat:@"/%@%@", self.bucketName, self.resourcePath]];

    return result;
}

- (NSString *)authorizationHeader
{
    NSData *encryptedStringData = [[self stringToSign] encryptWithKey:self.secretKey];
    NSString *authToken = [encryptedStringData base64EncodedString];
    return [NSString stringWithFormat:@"AWS %@:%@", self.accessKey, authToken];
}

- (void)setHTTPBody:(NSData *)body
{
	[super setHTTPBody:body];
	[self addValue:[body md5SignatureBase64] forHTTPHeaderField:@"Content-Md5"];
}

- (void)prepareURL
{	
    NSString *urlString = [self composedURLString];
	[self setURL:[NSURL URLWithString:urlString]];
}

- (void)sign
{
    [self setValue:[self authorizationHeader] forHTTPHeaderField:@"Authorization"];
}

- (void)show
{
	printf("bucketName   = %s\n", [self.bucketName UTF8String]);
	printf("resourcePath = %s\n", [self.resourcePath UTF8String]);
	printf("composedURLString = %s\n", [[self composedURLString] UTF8String]);
	printf("HTTPMethod   = %s\n", [self.HTTPMethod UTF8String]);	
	printf("parameters   = %s\n", [[self.parameters description] UTF8String]);
	printf("allHTTPHeaderFields = %s\n", [[self.allHTTPHeaderFields description] UTF8String]);
	printf("stringToSign = [[%s]]\n", [[self stringToSign] UTF8String]);
}

@end
