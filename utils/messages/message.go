package messages

import (
	"fmt"
)

func BuildValidationResponseBy(err error, entity string) (int, body) {
	message := fmt.Sprintf("failed to validate the fields of the %v", entity)
	return validationResponse(message, err)
}

func BuildResponseBy(err error) (int, body) {
	errorMessage := err.Error()
	return readFromMap(errorMessage)
}
