//
//  BS3Request.h
//  BS3Request
//
//  Created by Brandon Smith on 7/15/12.
//  Copyright (c) 2012 TokenGnome. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface BS3Request : NSMutableURLRequest

// Initialize a new BS3Request object
// @param bucketName The name of the bucket to perform the request on or nil
// @param resourcePath The path to the resouce targeted by the request.
// @param params The dictionary of special request parameters to use
//        @see http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTBucketGET.html#RESTBucketGET-requests-request-parameters
// @param accessKey The Amazon AWS access key to be used to sign the request
// @param secretKey The Amazon AWS secret key to be used to sign the request
// @return a newly initialized NSURLRequest subclass with a signed URL
- (id)initWithBucketName:(NSString *)bucketName
            resourcePath:(NSString *)resourcePath
              parameters:(NSDictionary *)params
               accessKey:(NSString *)accessKey
               secretKey:(NSString *)secretKey;

// Must be called prior to starting the request. Computes and sets the authorization header based on the the
// HTTP method of, MD5 hash of the HTTP body, etc.
- (void)setAuthorizationHeader;

@end
