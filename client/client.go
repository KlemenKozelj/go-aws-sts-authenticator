package client

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

const body string = "Action=GetCallerIdentity&Version=2011-06-15"

var requestBodySha256 string = getSHA256Hash(body)

type StsAuthenticator struct {
	awsRegion string
	signer    *v4.Signer
	stsClient *sts.Client
}

func NewClient(ctx context.Context) (*StsAuthenticator, error) {
	client := StsAuthenticator{
		signer: v4.NewSigner(),
	}
	configuration, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}
	client.awsRegion = configuration.Region
	client.stsClient = sts.NewFromConfig(configuration)
	return &client, nil
}

func (c StsAuthenticator) getTemporarilyAwsCredentials(ctx context.Context) (*aws.Credentials, error) {
	result, err := c.stsClient.GetSessionToken(ctx, &sts.GetSessionTokenInput{})
	if err != nil {
		return nil, err
	}
	awsCredentials := credentials.NewStaticCredentialsProvider(
		*result.Credentials.AccessKeyId,
		*result.Credentials.SecretAccessKey,
		*result.Credentials.SessionToken,
	)
	credentials, err := awsCredentials.Retrieve(ctx)
	if err != nil {
		return nil, err
	}
	return &credentials, nil
}

func (c StsAuthenticator) GetStsParameters(ctx context.Context) (xAmzDate, authorization, xAmzSecurityToken, awsRegion string, err error) {
	awsCredentials, err := c.getTemporarilyAwsCredentials(ctx)
	if err != nil {
		return "", "", "", "", err
	}
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("https://sts.%s.amazonaws.com", c.awsRegion), strings.NewReader(body))
	if err != nil {
		return "", "", "", "", err
	}
	err2 := c.signer.SignHTTP(ctx, *awsCredentials, req, requestBodySha256, "sts", c.awsRegion, time.Now())
	if err2 != nil {
		return "", "", "", "", err2
	}
	return req.Header.Get("X-Amz-Date"), req.Header.Get("Authorization"), req.Header.Get("X-Amz-Security-Token"), c.awsRegion, nil
}

func (c StsAuthenticator) SignRequest(req *http.Request) error {
	awsCredentials, err := c.getTemporarilyAwsCredentials(req.Context())
	if err != nil {
		return err
	}
	err2 := c.signer.SignHTTP(req.Context(), *awsCredentials, req, requestBodySha256, "sts", c.awsRegion, time.Now())
	if err2 != nil {
		return err2
	}
	return nil
}

func getSHA256Hash(input string) string {
	hash := sha256.New()
	hash.Write([]byte(input))
	hashBytes := hash.Sum(nil)
	hashString := hex.EncodeToString(hashBytes)
	return hashString
}
