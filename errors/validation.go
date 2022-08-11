package errors

import (
	"errors"
)

var (
	// validation errors
	ErrEmailUpdateNotAllowed     = errors.New("email update not allowed")
	ErrUserNameUpdateNotAllowed  = errors.New("username update not allowed")
	ErrPasswordUpdateNotAllowed  = errors.New("password update not allowed")
	ErrInvalidLoginProvider      = errors.New("invalid login provider")
	ErrEmailAlreadyRegistered    = errors.New("email is already taken")
	ErrUserNameAlreadyRegistered = errors.New("username is already taken")
)
