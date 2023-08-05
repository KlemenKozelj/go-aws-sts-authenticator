package server

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"
)

var httpClient *http.Client = &http.Client{}

type awsGetCallerIdentityResponse struct {
	XMLName                 xml.Name `xml:"GetCallerIdentityResponse"`
	GetCallerIdentityResult struct {
		Arn     string `xml:"Arn"`
		UserId  string `xml:"UserId"`
		Account string `xml:"Account"`
	} `xml:"GetCallerIdentityResult"`
	ResponseMetadata struct {
		RequestId string `xml:"RequestId"`
	} `xml:"ResponseMetadata"`
}

func StsGetCallerIdentity(url, xAmzDate, authorization, xAmzSecurityToken string) (*awsGetCallerIdentityResponse, error) {

	paramNames := []string{"url", "x-amz-date", "authorization", "x-amz-security-token"}
	parameters := []string{url, xAmzDate, authorization, xAmzSecurityToken}
	for i, param := range parameters {
		if param == "" {
			return nil, errorCustom{Type: AwsStsInvalidParameter, Err: fmt.Errorf("%s is empty", paramNames[i])}
		}
	}

	body := "Action=GetCallerIdentity&Version=2011-06-15"
	request, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		return nil, errorCustom{Type: AwsStsRequestError, Err: err}
	}

	request.Header.Set("X-Amz-Date", xAmzDate)
	request.Header.Set("Authorization", authorization)
	request.Header.Set("X-Amz-Security-Token", xAmzSecurityToken)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Host", "sts.amazonaws.com")
	request.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))

	response, err := httpClient.Do(request)
	if err != nil {
		return nil, errorCustom{Type: AwsStsServerError, Err: err}
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, errorCustom{Type: AWSStsServerRejection, Err: fmt.Errorf("aws sts server response status: %s", response.Status)}
	}

	var responseAwsCallerIdentity awsGetCallerIdentityResponse
	err2 := xml.NewDecoder(response.Body).Decode(&responseAwsCallerIdentity)
	if err2 != nil {
		return nil, errorCustom{Type: AWSStsServerResponse, Err: err2}
	}

	return &responseAwsCallerIdentity, nil
}
