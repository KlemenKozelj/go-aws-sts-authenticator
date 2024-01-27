package main

import (
	"context"
	"fmt"
	"net/http"

	"github.com/klemenkozelj/go-aws-sts-authenticator/client"
	"github.com/klemenkozelj/go-aws-sts-authenticator/server"
)

func main() {

	xAmzDate, authorization, xAmzSecurityToken, awsRegion := clientExample()

	serverExample(xAmzDate, authorization, xAmzSecurityToken, awsRegion)

	mux := http.NewServeMux()

	awsAuth := server.AuthenticateAwsIamIdentity(
		server.DefaultGetRequestParameters,
		server.DefaultIsIamIdentityValid("arn:aws:iam::1234567890:user/username"),
	)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Your handler is running!")
	})

	mux.Handle("/", awsAuth(handler))

}

func clientExample() (string, string, string, string) {

	ctx := context.Background()

	signatureClient, err := client.NewClient(ctx)
	if err != nil {
		panic(err)
	}

	xAmzDate, authorization, xAmzSecurityToken, awsRegion, err := signatureClient.GetStsParameters(ctx)
	if err != nil {
		panic(err)
	}

	return xAmzDate, authorization, xAmzSecurityToken, awsRegion

}

func serverExample(date, authorization, token, region string) {

	identity, err := server.StsGetCallerIdentity("https://sts."+region+".amazonaws.com", date, authorization, token)
	if err != nil {
		panic(err)
	}

	fmt.Println("AWS IAM ARN = ", identity.GetCallerIdentityResult.Arn)

}
