package rest_errors

import "fmt"

func Create(entity string) string {
	return fmt.Sprintf("failed to create %v", entity)
}

func Update(entity string) string {
	return fmt.Sprintf("failed to update %v", entity)
}

func Store(entity string) string {
	return fmt.Sprintf("failed to store %v", entity)
}

func Reset(entity string) string {
	return fmt.Sprintf("failed to reset %v", entity)
}

func Fetch(entity string) string {
	return fmt.Sprintf("failed to fetch the %v", entity)
}

func Count(entity string) string {
	return fmt.Sprintf("failed to count the %v", entity)
}

func Delete(entity string) string {
	return fmt.Sprintf("failed to delete the %v", entity)
}

func NotFound(entity string) string {
	return fmt.Sprintf("%v not found", entity)
}

func UpdateCache(entity string) string {
	return fmt.Sprintf("failed to update %v in the cache", entity)
}
