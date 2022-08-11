package errors

import (
	"fmt"
	"net/http"
)

func Create(entity string) error {
	message = fmt.Sprintf("failed to create %v", entity)
	return buildErrorWithHttpCode(message, http.StatusInternalServerError)
}

func Update(entity string) error {
	message = fmt.Sprintf("failed to update %v", entity)
	return buildErrorWithHttpCode(message, http.StatusInternalServerError)
}

func Store(entity string) error {
	message = fmt.Sprintf("failed to store %v", entity)
	return buildErrorWithHttpCode(message, http.StatusInternalServerError)
}

func Fetch(entity string) error {
	message = fmt.Sprintf("failed to fetch the %v", entity)
	return buildErrorWithHttpCode(message, http.StatusInternalServerError)
}

func Count(entity string) error {
	message = fmt.Sprintf("failed to count the %v", entity)
	return buildErrorWithHttpCode(message, http.StatusInternalServerError)
}

func Delete(entity string) error {
	message = fmt.Sprintf("failed to delete the %v", entity)
	return buildErrorWithHttpCode(message, http.StatusInternalServerError)
}

func NotFound(entity string) error {
	message = fmt.Sprintf("%v not found", entity)
	return buildErrorWithHttpCode(message, http.StatusNotFound)
}

func Invalid(attribute string) error {
	message = fmt.Sprintf("invalid %v", attribute)
	return buildErrorWithHttpCode(message, http.StatusUnauthorized)
}

func UpdateCache(entity string) error {
	message = fmt.Sprintf("failed to update %v in the cache", entity)
	return buildErrorWithHttpCode(message, http.StatusInternalServerError)
}
