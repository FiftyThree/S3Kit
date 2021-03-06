//
//  BS3Request.h
//  BS3Request
//
//  Created by Brandon Smith on 7/15/12.
//  Copyright (c) 2012 TokenGnome. All rights reserved.
//
// @param bucketName The name of the bucket to perform the request on or nil
// @param resourcePath The path to the resouce targeted by the request.
// @param params The dictionary of special request parameters to use
//        @see http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTBucketGET.html#RESTBucketGET-requests-request-parameters
// @param accessKey The Amazon AWS access key to be used to sign the request
// @param secretKey The Amazon AWS secret key to be used to sign the request
// @return a newly initialized NSURLRequest subclass with a signed URL


#import <Foundation/Foundation.h>

@interface BS3Request : NSMutableURLRequest
{
}

@property (nonatomic, retain) NSDate *date;
@property (nonatomic, retain) NSString *bucketName;
@property (nonatomic, retain) NSString *resourcePath;
@property (nonatomic, retain) NSString *accessKey;
@property (nonatomic, retain) NSString *secretKey;
@property (nonatomic, retain) NSString *redirectUrlString;


@property (nonatomic, retain) NSMutableDictionary *parameters;
@property (assign) BOOL usesSSL;


// Computes and sets the authorization header based on the the
// HTTP method of, MD5 hash of the HTTP body, etc.
// so don't change those after set up

- (NSString *)stringToSign;
- (NSString *)authorizationHeader;

- (void)prepareURL;
- (void)sign;

- (void)show;

// sending
/*
@property (nonatomic, retain) NSHTTPURLResponse *response;
@property (nonatomic, retain) NSError *error;
@property (nonatomic, retain) NSMutableData *responseData;
@property (nonatomic, assign) BOOL isDone;
@property (nonatomic, assign) NSOutputStream *outputStream;

- (void)syncSend;
*/
@end
