package server

import (
	"fmt"
	"net/http"
)

type GetRequestParameters func(r *http.Request) (awsRegion, xAmzDate, xAmzSecurityToken, authorization string, err error)
type IsIamIdentityValid func(awsIamIdentityArn string) (valid bool)

func DefaultGetRequestParameters(r *http.Request) (awsRegion, xAmzDate, xAmzSecurityToken, authorization string, err error) {
	xAmzDate = r.Header.Get("x-amz-date")
	if xAmzDate == "" {
		return "", "", "", "", errorCustom{Type: AwsStsInvalidParameter, Err: fmt.Errorf("missing x-amz-date header")}
	}
	xAmzSecurityToken = r.Header.Get("x-amz-security-token")
	if xAmzSecurityToken == "" {
		return "", "", "", "", errorCustom{Type: AwsStsInvalidParameter, Err: fmt.Errorf("missing x-amz-security-token header")}
	}
	authorization = r.Header.Get("authorization")
	if authorization == "" {
		return "", "", "", "", errorCustom{Type: AwsStsInvalidParameter, Err: fmt.Errorf("missing authorization header")}
	}
	awsRegion = getAwsIamRegion(authorization)
	if awsRegion == "" {
		return "", "", "", "", errorCustom{Type: AwsStsInvalidParameter, Err: fmt.Errorf("missing AWS IAM region")}
	}
	return awsRegion, xAmzDate, xAmzSecurityToken, authorization, nil
}

func DefaultIsIamIdentityValid(awsIamIdentityArns ...string) IsIamIdentityValid {
	authorized := make(map[string]bool)
	for _, awsIamArn := range awsIamIdentityArns {
		if !isValidAwsIamArn(awsIamArn) {
			panic("invalid AWS IAM ARN specified " + awsIamArn)
		}
		authorized[awsIamArn] = true
	}
	return func(awsIamIdentityArn string) bool {
		return authorized[awsIamIdentityArn]
	}
}

var getAwsStsUrl = func(awsRegion string) string {
	return fmt.Sprintf("https://sts.%s.amazonaws.com", awsRegion)
}

func AuthenticateAwsIamIdentity(getRequestParameters GetRequestParameters, isIamIdentityValid IsIamIdentityValid) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			awsRegion, xAmzDate, xAmzSecurityToken, authorization, err := getRequestParameters(r)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			awsCallerIdentity, err := StsGetCallerIdentity(getAwsStsUrl(awsRegion), xAmzDate, xAmzSecurityToken, authorization)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if !isIamIdentityValid(awsCallerIdentity.GetCallerIdentityResult.Arn) {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
