package rest_errors

import (
	"errors"
	"net/http"

	"auth/consts"
)

// Map for errors with http code

var ResponseCode = make(map[string]int)

func ResponseMap() map[string]int {
	return ResponseCode
}

func NewError(message string, httpCode int) error {
	_, available := ResponseCode[message]
	if !available {
		ResponseCode[message] = httpCode
	}
	return errors.New(message)
}

var (

	// Common
	ErrCopyStruct    = NewError("failed to copy the structs", http.StatusInternalServerError)
	ErrMissingParams = NewError("params not found in the request", http.StatusBadRequest)

	// Controller
	ErrParsingRequestBody = NewError("failed to parse request body", http.StatusBadRequest)
	NoLoggedInUserFound   = NewError("no logged-in user found", http.StatusUnauthorized)
	AccessForbidden       = NewError("access forbidden", http.StatusForbidden)

	// Service
	ErrLogin                      = NewError("invalid email or password", http.StatusUnauthorized)
	ErrLogOut                     = NewError("failed to logout", http.StatusInternalServerError)
	ErrSamePassword               = NewError("password can't be same as old one", http.StatusBadRequest)
	ErrUpdatingPassword           = NewError(Update(consts.Password), http.StatusInternalServerError)
	ErrResettingPassword          = NewError(Update(consts.Password), http.StatusInternalServerError)
	ErrResendingForgotPasswordOTP = NewError("failed to resend the OTP", http.StatusInternalServerError)
	ErrCreatingForgotPasswordOTP  = NewError("failed to create the OTP", http.StatusInternalServerError)
	InvalidPassword               = NewError(Invalid(consts.Password), http.StatusUnauthorized)
	InvalidAccessToken            = NewError(Invalid(consts.AccessToken), http.StatusUnauthorized)
	InvalidRefreshToken           = NewError(Invalid(consts.RefreshToken), http.StatusUnauthorized)
	InvalidResetToken             = NewError(Invalid(consts.ResetToken), http.StatusUnauthorized)
	InvalidSocialLoginToken       = NewError(Invalid(consts.SocialLoginToken), http.StatusUnauthorized)
	InvalidOTP                    = NewError(Invalid(consts.OTP), http.StatusUnauthorized)
	InvalidOTPNonce               = NewError(Invalid(consts.OTPNonce), http.StatusUnauthorized)
	InvalidJWTToken               = NewError(Invalid(consts.JWTToken), http.StatusUnauthorized)
	InvalidSigningMethod          = NewError("invalid signing method while parsing jwt", http.StatusUnauthorized)
	InvalidPasswordFormat         = NewError("minimum 8 characters with at least 1 uppercase letter(A-Z), 1 lowercase letter(a-z), 1 number(0-9) and 1 special character(.!@#~$%^&*()+|_<>)", http.StatusBadRequest)
	InvalidLoginAttemptHink       = NewError(InvalidLoginAttempt(consts.LoginProviderHink), http.StatusUnauthorized)
	InvalidLoginAttemptGoogle     = NewError(InvalidLoginAttempt(consts.LoginProviderGoogle), http.StatusUnauthorized)
	InvalidLoginAttemptFacebook   = NewError(InvalidLoginAttempt(consts.LoginProviderFacebook), http.StatusUnauthorized)
	InvalidLoginAttemptApple      = NewError(InvalidLoginAttempt(consts.LoginProviderApple), http.StatusUnauthorized)
	ErrParsingJWTToken            = NewError(Parse(consts.JWTToken), http.StatusInternalServerError)
	ErrStoringJWTToken            = NewError(Store(consts.JWTToken), http.StatusInternalServerError)
	ErrCreatingJWTToken           = NewError(Create(consts.JWTToken), http.StatusInternalServerError)
	ErrDeletingOldJWTToken        = NewError(Delete(consts.OldToken), http.StatusInternalServerError)
	ErrSigningAccessToken         = NewError(SignToken(consts.AccessToken), http.StatusInternalServerError)
	ErrSigningRefreshToken        = NewError(SignToken(consts.RefreshToken), http.StatusInternalServerError)

	// Repository
	// User
	ErrCreatingUser           = NewError(Create(consts.User), http.StatusInternalServerError)
	ErrUpdatingUser           = NewError(Update(consts.User), http.StatusInternalServerError)
	ErrUpdatingUserMetaData   = NewError(Update(consts.MetaData), http.StatusInternalServerError)
	ErrUpdatingUserProfilePic = NewError(Update(consts.ProfilePic), http.StatusInternalServerError)
	ErrUpdatingUserStat       = NewError(Update(consts.Stat), http.StatusInternalServerError)
	ErrDeletingUser           = NewError(Delete(consts.User), http.StatusInternalServerError)
	ErrFetchingUsers          = NewError(Fetch(consts.Users), http.StatusInternalServerError)
	ErrCountingUsers          = NewError(Count(consts.Users), http.StatusInternalServerError)
	ErrUpdatingCacheUser      = NewError(UpdateCache(consts.User), http.StatusInternalServerError)
	UserNotFound              = NewError(NotFound(consts.User), http.StatusNotFound)

	// validation errors
	ErrEmailUpdateNotAllowed     = NewError("email update not allowed", http.StatusBadRequest)
	ErrUserNameUpdateNotAllowed  = NewError("username update not allowed", http.StatusBadRequest)
	ErrPasswordUpdateNotAllowed  = NewError("password update not allowed", http.StatusBadRequest)
	ErrInvalidLoginProvider      = NewError("invalid login provider", http.StatusBadRequest)
	ErrEmailAlreadyRegistered    = NewError("email is already taken", http.StatusBadRequest)
	ErrUserNameAlreadyRegistered = NewError("username is already taken", http.StatusBadRequest)
)
