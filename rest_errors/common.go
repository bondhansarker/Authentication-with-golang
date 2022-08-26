package rest_errors

import "fmt"

// Authentication based

func InvalidLoginAttempt(provider string) string {
	return fmt.Sprintf("user is registered via %v", provider)
}

func Parse(tokenType string) string {
	return fmt.Sprintf("failed to parse %v", tokenType)
}

func Store(entity interface{}) string {
	return fmt.Sprintf("failed to store %v", entity)
}

func SignToken(tokenType string) string {
	return fmt.Sprintf("failed to sign %v", tokenType)
}

func Invalid(attribute string) string {
	return fmt.Sprintf("invalid %v", attribute)
}

// Resource based

func Create(entity interface{}) string {
	return fmt.Sprintf("failed to create %v", entity)
}

func Update(entity interface{}) string {
	return fmt.Sprintf("failed to update %v", entity)
}

func Fetch(entity interface{}) string {
	return fmt.Sprintf("failed to fetch the %v", entity)
}

func Count(entity interface{}) string {
	return fmt.Sprintf("failed to count the %v", entity)
}

func Delete(entity interface{}) string {
	return fmt.Sprintf("failed to delete the %v", entity)
}

func NotFound(entity interface{}) string {
	return fmt.Sprintf("%v not found", entity)
}

func UpdateCache(entity interface{}) string {
	return fmt.Sprintf("failed to update %v in the cache", entity)
}
