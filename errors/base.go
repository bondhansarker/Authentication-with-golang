package errors

import (
	"auth/utils/messages"
	"errors"
)

var message string

func buildErrorWithHttpCode(message string, httpStatus int) error {
	messages.AddToMap(message, httpStatus)
	err := errors.New(message)
	return err
}
