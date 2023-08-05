package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

const (
	awsRegionBase         = "eu-central-1"
	xAmzDateBase          = "20230730T101440Z"
	xAmzSecurityTokenBase = "thisIsSecurityToken"
	authorizationBase     = "AWS4-HMAC-SHA256 Credential=CREDENTIALS/20230730/" + awsRegionBase + "/sts/aws4_request, SignedHeaders=content-length;host;x-amz-date;x-amz-security-token, Signature=signature"
)

func TestDefaultGetRequestParameters(t *testing.T) {

	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://sts.%s.amazonaws.com", awsRegionBase), nil)
	var err error

	_, _, _, _, err = DefaultGetRequestParameters(req)
	if err == nil {
		t.Errorf("Expected error since no default headers were provided")
	}
	req.Header.Set("x-amz-date", xAmzDateBase)
	_, _, _, _, err = DefaultGetRequestParameters(req)
	if err == nil {
		t.Errorf("Expected error since only x-amz-date was provided")
	}
	req.Header.Set("x-amz-security-token", xAmzSecurityTokenBase)
	_, _, _, _, err = DefaultGetRequestParameters(req)
	if err == nil {
		t.Errorf("Expected error since only x-amz-date and x-amz-security-token were provided")
	}

	req.Header.Set("authorization", authorizationBase)
	awsRegion, xAmzDate, xAmzSecurityToken, authorization, err := DefaultGetRequestParameters(req)
	if err != nil {
		t.Errorf("Expected no error since all parameters were provided")
	}
	if awsRegion != awsRegionBase {
		t.Errorf("Expected %s, but got %s", awsRegionBase, awsRegion)
	}
	if xAmzDate != xAmzDateBase {
		t.Errorf("Expected %s, but got %s", xAmzDateBase, xAmzDate)
	}
	if xAmzSecurityToken != xAmzSecurityTokenBase {
		t.Errorf("Expected %s, but got %s", xAmzSecurityTokenBase, xAmzSecurityToken)
	}
	if authorization != authorizationBase {
		t.Errorf("Expected %s, but got %s", authorizationBase, authorization)
	}

}

func TestDefaultIsIamIdentityValid(t *testing.T) {

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Expected panic with invalid ARN, but got none")
		}
	}()
	DefaultIsIamIdentityValid("invalid-arn")

	validator := DefaultIsIamIdentityValid(
		"arn:aws:iam::1234567890:user/username1",
		"arn:aws:iam::1234567890:role/username2",
	)
	if !validator("arn:aws:iam::1234567890:user/username1") {
		t.Errorf("Expected username1 to be valid, but got invalid")
	}
	if !validator("arn:aws:iam::1234567890:role/username2") {
		t.Errorf("Expected username2 to be valid, but got invalid")
	}
	if validator("arn:aws:iam::1234567890:role/username3") {
		t.Errorf("Expected username3 invalid ARN to be invalid, but got valid")
	}
	if validator("invalid-arn") {
		t.Errorf("Expected invalid arn invalid ARN to be invalid, but got valid")
	}
}

func TestAuthenticateAwsIamIdentity(t *testing.T) {

	testAwsStsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("Authorization") {
		case "wrongStsCredentials":
			w.WriteHeader(http.StatusUnauthorized)
			return
		case "invalidIamArn":
			xmlResponse := `
			<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
				<GetCallerIdentityResult>
					<Arn>arn:aws:iam::1234567890:user/username</Arn>
					<UserId>AKIATESTACCESSKEY</UserId>
					<Account>1234567890</Account>
				</GetCallerIdentityResult>
				<ResponseMetadata>
					<RequestId>7ae1ff87-8867-4b21-916b-4b44bef35345</RequestId>
				</ResponseMetadata>
			</GetCallerIdentityResponse>`
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, xmlResponse)
			return
		case "validIamArn":
			xmlResponse := `
			<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
				<GetCallerIdentityResult>
					<Arn>arn:aws:iam::1234567890:user/username1</Arn>
					<UserId>AKIATESTACCESSKEY</UserId>
					<Account>1234567890</Account>
				</GetCallerIdentityResult>
				<ResponseMetadata>
					<RequestId>7ae1ff87-8867-4b21-916b-4b44bef35345</RequestId>
				</ResponseMetadata>
			</GetCallerIdentityResponse>`
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, xmlResponse)
			return
		}
		t.FailNow()
	}))
	defer testAwsStsServer.Close()
	getAwsStsUrl = func(awsRegion string) string {
		return testAwsStsServer.URL
	}

	authenticateMiddleware := AuthenticateAwsIamIdentity(
		func(r *http.Request) (awsRegion, xAmzDate, xAmzSecurityToken, authorization string, err error) {
			switch r.URL.Query().Get("scenario") {
			case "badRequest":
				return "", "", "", "", fmt.Errorf("bad request")
			case "wrongStsCredentials":
				return "eu-central-1", "20230730T101440Z", "wrongStsCredentials", "AWS4-HMAC-SHA256...", nil
			case "invalidIamArn":
				return "eu-central-1", "20230730T101440Z", "invalidIamArn", "AWS4-HMAC-SHA256...", nil
			case "validIamArn":
				return "eu-central-1", "20230730T101440Z", "validIamArn", "AWS4-HMAC-SHA256...", nil
			}
			t.FailNow()
			return "", "", "", "", nil
		},
		func(awsIamIdentityArn string) bool {
			return awsIamIdentityArn == "arn:aws:iam::1234567890:user/username1"
		},
	)

	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	requestRecorder1 := httptest.NewRecorder()
	request1 := httptest.NewRequest(http.MethodGet, "http://localhost:8080/?scenario=badRequest", nil)
	authenticateMiddleware(mockHandler).ServeHTTP(requestRecorder1, request1)
	if requestRecorder1.Code != http.StatusBadRequest {
		t.Errorf("Expected status code %d, but got %d", http.StatusBadRequest, requestRecorder1.Code)
	}

	requestRecorder2 := httptest.NewRecorder()
	request2 := httptest.NewRequest(http.MethodGet, "http://localhost:8080/?scenario=wrongStsCredentials", nil)
	authenticateMiddleware(mockHandler).ServeHTTP(requestRecorder2, request2)
	if requestRecorder2.Code != http.StatusInternalServerError {
		t.Errorf("Expected status code %d, but got %d", http.StatusInternalServerError, requestRecorder2.Code)
	}

	requestRecorder3 := httptest.NewRecorder()
	request3 := httptest.NewRequest(http.MethodGet, "http://localhost:8080/?scenario=invalidIamArn", nil)
	authenticateMiddleware(mockHandler).ServeHTTP(requestRecorder3, request3)
	if requestRecorder3.Code != http.StatusUnauthorized {
		t.Errorf("Expected status code %d, but got %d", http.StatusUnauthorized, requestRecorder3.Code)
	}

	requestRecorder4 := httptest.NewRecorder()
	request4 := httptest.NewRequest(http.MethodGet, "http://localhost:8080/?scenario=validIamArn", nil)
	authenticateMiddleware(mockHandler).ServeHTTP(requestRecorder4, request4)
	if requestRecorder4.Code != http.StatusOK {
		t.Errorf("Expected status code %d, but got %d", http.StatusOK, requestRecorder4.Code)
	}
}
