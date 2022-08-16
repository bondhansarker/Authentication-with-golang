package rest_errors

import "fmt"

func InvalidLoginAttempt(provider string) string {
	return fmt.Sprintf("user is registered via %v", provider)
}

func ParseToken(tokenType string) string {
	return fmt.Sprintf("failed to parse %v", tokenType)
}

func SignToken(tokenType string) string {
	return fmt.Sprintf("failed to sign %v", tokenType)
}

func Invalid(attribute string) string {
	return fmt.Sprintf("invalid %v", attribute)
}
