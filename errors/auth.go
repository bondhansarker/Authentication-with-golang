package errors

import (
	"fmt"
	"net/http"
)

func SamePassword() error {
	message = "password can't be same as old one"
	return buildErrorWithHttpCode(message, http.StatusBadRequest)
}

func ResetPassword() error {
	message = "failed to reset password"
	return buildErrorWithHttpCode(message, http.StatusInternalServerError)
}

func LogoutFailed() error {
	message = "failed to logout"
	return buildErrorWithHttpCode(message, http.StatusInternalServerError)
}

func LoginFailed() error {
	message = "invalid email or password"
	return buildErrorWithHttpCode(message, http.StatusInternalServerError)
}

func AlreadyRegisteredVia(provider string) error {
	message = fmt.Sprintf("user already registered via %v", provider)
	return buildErrorWithHttpCode(message, http.StatusBadRequest)
}

func InvalidSigningMethod() error {
	message = fmt.Sprintf("invalid signing method while parsing jwt")
	return buildErrorWithHttpCode(message, http.StatusUnauthorized)
}

func InvalidPasswordFormat() error {
	message = fmt.Sprintf("minimum 8 characters with at least 1 uppercase letter(A-Z), 1 lowercase letter(a-z), 1 number(0-9) and 1 special character(.!@#~$%^&*()+|_<>)")
	return buildErrorWithHttpCode(message, http.StatusBadRequest)
}

func InvalidLoginAttempt(provider string) error {
	message = fmt.Sprintf("invalid login attempt via %v", provider)
	return buildErrorWithHttpCode(message, http.StatusUnprocessableEntity)
}

func ParseToken(tokenType string) error {
	message = fmt.Sprintf("failed to parse %v", tokenType)
	return buildErrorWithHttpCode(message, http.StatusUnauthorized)
}

func SignToken(tokenType string) error {
	message = fmt.Sprintf("failed to sign %v", tokenType)
	return buildErrorWithHttpCode(message, http.StatusInternalServerError)
}
