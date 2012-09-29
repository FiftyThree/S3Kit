//
//  BS3Requestor.m
//  BS3Requestor
//
//

#import "BS3Requestor.h"
#import "NSData+Base64.h"
#import "NSData+MD5.h"
#import <CommonCrypto/CommonHMAC.h>
#import "NSString+Crypto.h"


@implementation BS3Requestor

@synthesize bucketName;
@synthesize resourcePath;
@synthesize accessKey;
@synthesize secretKey;

@synthesize HTTPMethod;
@synthesize allHTTPHeaderFields;
@synthesize HTTPBody;
@synthesize parameters;

@synthesize requestClass;
@synthesize usesSSL;

- (id)init
{
	self = [super init];
	allHTTPHeaderFields = [NSMutableDictionary dictionary];
	parameters = [NSMutableDictionary dictionary];
	HTTPMethod = @"GET";
	requestClass = [NSMutableURLRequest class];
	usesSSL = YES;
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
    if (!parameters || [[parameters allKeys] count] < 1) return @"";
    static NSSet *validParameters;
    if (!validParameters) validParameters = [NSSet setWithObjects:@"delimiter",
                                             @"marker",
                                             @"max-keys",
                                             @"delimiter",
                                             @"prefix", nil];
    NSString *paramStr = @"";
    for (NSString *key in [parameters allKeys])
    {
        paramStr = [validParameters containsObject:key] ?
        [paramStr stringByAppendingFormat:@"&%@=%@",
         key,
         [BS3Requestor urlEncodedParameter:[parameters objectForKey:key]]] :
        paramStr;
    }
    NSLog(@"%@", paramStr);

    return ([paramStr isEqualToString:@""] ?
            @"" :
            [paramStr stringByReplacingCharactersInRange:NSMakeRange(0, 1) withString:@""]);
}

- (NSString *)composedURLString
{
	NSString *scheme = usesSSL ? @"https" : @"http";

    NSString *urlString = [NSString stringWithFormat:@"%@://s3.amazonaws.com/%@%@",
						scheme, bucketName, resourcePath];

    NSString *parameterString = [self stringForParameters];
	
    if (parameterString.length > 0)
    {
        urlString = [urlString stringByAppendingFormat:@"?%@", parameterString];
    }

    return urlString;
}


- (NSString *)dateHeader
{
    return [BS3Requestor dateHeaderForDate:[NSDate date]];
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

- (NSString *)authorizationHeader
{
	NSLog(@"secretKey = '%@'", secretKey);
    NSData *encryptedStringData = [[self stringToSign] encryptWithKey:secretKey];
    NSString *authToken = [encryptedStringData base64EncodedString];
    return [NSString stringWithFormat:@"AWS %@:%@", accessKey, authToken];
}

- (NSMutableURLRequest *)composedRequest
{
	//[self show];
    NSString *urlString = [self composedURLString];

    NSMutableURLRequest *request = [[requestClass alloc] initWithURL:[NSURL URLWithString:urlString]];
	
    [allHTTPHeaderFields setObject:[self dateHeader] forKey:@"Date"];
	
    if (HTTPBody)
    {
        [request setValue:[HTTPBody md5Signature] forHTTPHeaderField:@"Content-Md5"];
    }
	
	// copy values to request
	
	request.HTTPMethod = HTTPMethod;
	
	for (NSString *key in [allHTTPHeaderFields allKeys])
	{
        [request setValue:[allHTTPHeaderFields objectForKey:key] forHTTPHeaderField:key];
	}
	
    if (self.HTTPBody)
    {
		request.HTTPBody = self.HTTPBody;
    }

    [request setValue:[self authorizationHeader] forHTTPHeaderField:@"Authorization"];
	return request;
}

- (void)show
{
	printf("bucketName = %s\n", [bucketName UTF8String]);
	printf("resourcePath = %s\n", [resourcePath UTF8String]);
	printf("HTTPMethod = %s\n", [self.HTTPMethod UTF8String]);	
	printf("parameters = %s\n", [[parameters description] UTF8String]);
	printf("allHTTPHeaderFields = %s\n", [[allHTTPHeaderFields description] UTF8String]);
}

@end
