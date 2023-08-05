package server

import "testing"

func TestIsValidAwsIamArn(t *testing.T) {
	testCases := []struct {
		input    string
		expected bool
	}{
		{"", false},
		{"arn:aws:iam::1234567890:user", false},
		{"arn:aws:iam::1234567890:/username", false},
		{"arn:aws:iam:::user/username", false},
		{"arn:aws:::1234567890:user/username", false},
		{"arn::iam::1234567890:user/username", false},
		{"arn:aws:s3:::bucket-name", false},
		{"arn:aws:dynamodb:region:account-id:table/table-name", false},
		{"arn:aws:iam::1234567890:user/username/username", false},
		{"arn:aws:iam::1234567890:user/username", true},
		{"arn:aws:iam::1234567890:role/rolename", true},
	}

	for _, tc := range testCases {
		result := isValidAwsIamArn(tc.input)
		if result != tc.expected {
			t.Errorf("Input: %s, Expected: %t, Got: %t", tc.input, tc.expected, result)
		}
	}
}
func TestIsValidAwsRegion(t *testing.T) {
	testCases := []struct {
		input    string
		expected bool
	}{
		{"", false},
		{"us-west-2a", false},
		{"us-west-", false},
		{"uswest1", false},
		{"us-east-01", false},
		{"us-west", false},
		{"useast-1", false},
		{"us-east-10", false},
		{"us-east-a", false},
		{"us-east-01a", false},
		{"us-east-1", true},
		{"us-west-2", true},
		{"eu-central-1", true},
		{"ap-southeast-2", true},
		{"eu-west-1", true},
		{"sa-east-1", true},
		{"us-west-1", true},
	}

	for _, tc := range testCases {
		result := isValidAwsRegion(tc.input)
		if result != tc.expected {
			t.Errorf("Input: %s, Expected: %t, Got: %t", tc.input, tc.expected, result)
		}
	}
}

func TestGetAwsIamRegion(t *testing.T) {
	testCases := []struct {
		input     string
		awsRegion string
	}{
		{"", ""},
		{"AWS4-HMAC-SHA256-Credential=credential/20160126/us-east-1/sts/aws4_request, SignedHeaders=content-length;content-type;host;x-amz-date;x-amz-security-token, Signature=signature", ""},
		{"AWS4-HMAC-SHA256-Credential=credential/20160126/us-east-1/sts/aws4_request, Signature=signature", ""},
		{"Credential=credential/20160126/us-east-1/sts/aws4_request, SignedHeaders=content-length;content-type;host;x-amz-date;x-amz-security-token", ""},
		{"AWS4-HMAC-SHA256-Credential=credential/20160126/us-east-1/sts/aws4_request, SignedHeaders=content-length;content-type;host;x-amz-date;x-amz-security-token", ""},
		{"AWS4-HMAC-SHA256 Credential=credential/20160126/us-east-1/sts/aws4_request, SignedHeaders=content-length;content-type;host;x-amz-date;x-amz-security-token, Signature=signature", "us-east-1"},
	}

	for _, tc := range testCases {
		awsRegion := getAwsIamRegion(tc.input)
		if awsRegion != tc.awsRegion {
			t.Errorf("Input: %s, Expected region: %s, Got: %s", tc.input, tc.awsRegion, awsRegion)
		}
	}
}
