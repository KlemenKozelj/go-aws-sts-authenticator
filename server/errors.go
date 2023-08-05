package server

type ErrorType int

const (
	AwsStsInvalidParameter ErrorType = iota
	AwsStsRequestError
	AwsStsServerError
	AWSStsServerRejection
	AWSStsServerResponse
)

type errorCustom struct {
	Type ErrorType
	Err  error
}

func (se errorCustom) Error() string {
	return se.Err.Error()
}
