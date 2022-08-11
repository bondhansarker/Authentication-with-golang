package errors

import (
	"fmt"
	"net/http"
)

func NoLoggedInUserFound() error {
	message = "no logged-in user found"
	return buildErrorWithHttpCode(message, http.StatusUnauthorized)
}

func AccessForbidden() error {
	message = "access forbidden"
	return buildErrorWithHttpCode(message, http.StatusForbidden)
}

func CopyStruct() error {
	message = fmt.Sprintf("failed to copy the structs")
	return buildErrorWithHttpCode(message, http.StatusInternalServerError)
}

func ParseRequest() error {
	message = "failed to parse request body"
	return buildErrorWithHttpCode(message, http.StatusBadRequest)
}
