package server

import (
	"regexp"
	"strings"
)

func isValidAwsIamArn(awsIamIdentityArn string) bool {
	iamArnRegex := regexp.MustCompile(`^arn:aws:iam::[0-9]+:(user|role)/([a-zA-Z0-9_\.\-]+)$`)
	return iamArnRegex.MatchString(awsIamIdentityArn)
}

func isValidAwsRegion(awsRegion string) bool {
	awsRegionRegex := regexp.MustCompile(`^[a-z]{2}-[a-z]+-\d{1}$`)
	return awsRegionRegex.MatchString(awsRegion)
}

func getAwsIamRegion(authorization string) string {
	authorizationComponents := strings.Split(authorization, " ")
	if len(authorizationComponents) != 4 {
		return ""
	}
	authorizationCredentials := strings.Split(authorizationComponents[1], "/")
	if len(authorizationCredentials) != 5 {
		return ""
	}
	region := authorizationCredentials[2]
	if !isValidAwsRegion(region) {
		return ""
	}
	return region
}
