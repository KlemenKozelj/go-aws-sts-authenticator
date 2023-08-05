package server

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestStsGetCallerIdentity(t *testing.T) {

	var res *awsGetCallerIdentityResponse
	var err error
	var errServer errorCustom

	// Sending empty string url parameter
	res, err = StsGetCallerIdentity("", "", "", "")
	if res != nil {
		t.Errorf("Error is expected so response should be nil")
	}
	errors.As(err, &errServer)
	if errServer.Type != AwsStsInvalidParameter {
		t.Errorf("Server error type invalid request error was expected because url was empty string")
	}

	// Sending empty string date parameter
	res, err = StsGetCallerIdentity("url", "", "", "")
	if res != nil {
		t.Errorf("Error is expected so response should be nil")
	}
	errors.As(err, &errServer)
	if errServer.Type != AwsStsInvalidParameter {
		t.Errorf("Server error type invalid request error was expected because date was empty string")
	}

	// Sending empty string authorization parameter
	res, err = StsGetCallerIdentity("url", "date", "", "")
	if res != nil {
		t.Errorf("Error is expected so response should be nil")
	}
	errors.As(err, &errServer)
	if errServer.Type != AwsStsInvalidParameter {
		t.Errorf("Server error type invalid request error was expected because authorization was empty string")
	}

	// Sending empty string token parameter
	res, err = StsGetCallerIdentity("url", "date", "authorization", "")
	if res != nil {
		t.Errorf("Error is expected so response should be nil")
	}
	errors.As(err, &errServer)
	if errServer.Type != AwsStsInvalidParameter {
		t.Errorf("Server error type invalid request error was expected because token was empty string")
	}

	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queryParams := r.URL.Query()
		switch val := queryParams.Get("case"); val {
		case "notAcceptable":
			w.WriteHeader(http.StatusNotAcceptable)
		case "badResponse":
			xmlResponse := "this is not expected xml payload"
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, xmlResponse)
		case "goodResponse":
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
		default:
			t.FailNow()
		}
	}))
	defer testServer.Close()

	// Server returns 406 status code not acceptable response
	res, err = StsGetCallerIdentity(testServer.URL+"?case=notAcceptable", "date", "authorization", "token")
	if res != nil {
		t.Errorf("Error is expected so response should be nil")
	}
	errors.As(err, &errServer)
	if errServer.Type != AWSStsServerRejection {
		t.Errorf("Server error type invalid request error was expected because server returns 406 status code")
	}

	// Server returns bad response
	res, err = StsGetCallerIdentity(testServer.URL+"?case=badResponse", "date", "authorization", "token")
	if res != nil {
		t.Errorf("Error is expected so response should be nil")
	}
	errors.As(err, &errServer)
	if errServer.Type != AWSStsServerResponse {
		t.Errorf("Server error type invalid request error was expected because server returns bad response")
	}

	// Server returns good response
	res, err = StsGetCallerIdentity(testServer.URL+"?case=goodResponse", "date", "authorization", "token")
	if err != nil {
		t.Errorf("Good response is expected so response should be nil")
	}
	if res.GetCallerIdentityResult.Arn != "arn:aws:iam::1234567890:user/username" {
		t.Errorf("Returned server response should include users arn")
	}
}
