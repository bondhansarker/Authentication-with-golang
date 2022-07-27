package types

type ValidationError struct {
	Error   error  `json:"validation_error"`
	Message string `json:"message"`
}
