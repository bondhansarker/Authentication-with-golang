package response

import (
	"fmt"
	"net/http"

	"auth/rest_errors"
)

type body map[string]interface{}

func BuildValidationResponseBy(err error, entity string) (int, body) {
	message := fmt.Sprintf("failed to validate the fields of the %v", entity)
	return validationResponse(message, err)
}

func BuildResponseBy(err error) (int, body) {
	message := err.Error()
	return readFromMap(message)
}

func readFromMap(message string) (int, body) {
	httpStatus, available := rest_errors.ResponseMap()[message]
	if available {
		return httpStatus, generateResponseBody(message)
	}
	return http.StatusInternalServerError, generateResponseBody("something went wrong")
}

func generateResponseBody(message string) body {
	return body{
		"message": message,
	}
}

func validationResponse(message string, err error) (int, body) {
	return http.StatusBadRequest, body{
		"message":          message,
		"validation_error": err,
	}
}
