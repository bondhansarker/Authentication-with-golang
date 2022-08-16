package rest_errors

import (
	"net/http"

	"auth/consts"
)

var (
	// validation rest_errors
	ErrEmailUpdateNotAllowed     = "email update not allowed"
	ErrUserNameUpdateNotAllowed  = "username update not allowed"
	ErrPasswordUpdateNotAllowed  = "password update not allowed"
	ErrInvalidLoginProvider      = "invalid login provider"
	ErrEmailAlreadyRegistered    = "email is already taken"
	ErrUserNameAlreadyRegistered = "username is already taken"

	// Common

	NoLoggedInUserFound   = "no logged-in user found"
	AccessForbidden       = "access forbidden"
	ErrCopyStruct         = "failed to copy the structs"
	ErrParsingRequestBody = "failed to parse request body"
	ErrMissingParams      = "params not found in the request"

	// Auth
	ErrSamePassword         = "password can't be same as old one"
	ErrResetPassword        = "failed to reset password"
	ErrLogOut               = "failed to logout"
	ErrLogin                = "invalid email or password"
	InvalidPassword         = Invalid(consts.Password)
	InvalidAccessToken      = Invalid(consts.AccessToken)
	InvalidRefreshToken     = Invalid(consts.RefreshToken)
	InvalidResetToken       = Invalid(consts.ResetToken)
	InvalidSocialLoginToken = Invalid(consts.SocialLoginToken)
	InvalidOTP              = Invalid(consts.OTP)
	InvalidOldToken         = Invalid(consts.OldToken)
	InvalidOTPNonce         = Invalid(consts.OTPNonce)
	InvalidJWTToken         = Invalid(consts.JWTToken)

	InvalidSigningMethod        = "invalid signing method while parsing jwt"
	InvalidPasswordFormat       = "minimum 8 characters with at least 1 uppercase letter(A-Z), 1 lowercase letter(a-z), 1 number(0-9) and 1 special character(.!@#~$%^&*()+|_<>)"
	InvalidLoginAttemptHink     = InvalidLoginAttempt(consts.LoginProviderHink)
	InvalidLoginAttemptGoogle   = InvalidLoginAttempt(consts.LoginProviderGoogle)
	InvalidLoginAttemptFacebook = InvalidLoginAttempt(consts.LoginProviderFacebook)
	InvalidLoginAttemptApple    = InvalidLoginAttempt(consts.LoginProviderApple)

	// Token
	ErrParsingJWTToken     = ParseToken(consts.JWTToken)
	ErrStoringJWTToken     = Store(consts.JWTToken)
	ErrCreatingJWTToken    = Create(consts.JWTToken)
	ErrDeletingOldJWTToken = Delete(consts.OldToken)

	// Err Signing Errors
	ErrSigningAccessToken  = SignToken(consts.AccessToken)
	ErrSigningRefreshToken = SignToken(consts.RefreshToken)

	// User
	ErrCreatingUser               = Create(consts.User)
	ErrUpdatingUser               = Update(consts.User)
	ErrUpdatingUserMetaData       = Update(consts.MetaData)
	ErrUpdatingUserPassword       = Update(consts.Password)
	ErrResettingUserPassword      = Update(consts.Password)
	ErrUpdatingUserProfilePic     = Update(consts.ProfilePic)
	ErrUpdatingUserStat           = Update(consts.Stat)
	ErrDeletingUser               = Delete(consts.User)
	ErrFetchingUsers              = Fetch(consts.Users)
	ErrCountingUsers              = Count(consts.Users)
	ErrUpdatingCacheUser          = UpdateCache(consts.User)
	ErrResendingForgotPasswordOTP = "failed to resend the OTP"
	ErrCreatingForgotPasswordOTP  = "failed to create the OTP"
	UserNotFound                  = NotFound(consts.User)
)

// Http code
var ResponseCode = make(map[string]int)

func ResponseMap() map[string]int {
	return ResponseCode
}

func InitErrorMap() {

	// Bad Request
	ResponseCode[ErrSamePassword] = http.StatusBadRequest
	ResponseCode[InvalidPasswordFormat] = http.StatusBadRequest
	ResponseCode[ErrParsingRequestBody] = http.StatusBadRequest

	// Internal Server Error
	ResponseCode[ErrResetPassword] = http.StatusInternalServerError
	ResponseCode[ErrLogOut] = http.StatusInternalServerError
	ResponseCode[ErrLogin] = http.StatusInternalServerError
	ResponseCode[ErrSigningAccessToken] = http.StatusInternalServerError
	ResponseCode[ErrSigningRefreshToken] = http.StatusInternalServerError
	ResponseCode[ErrCopyStruct] = http.StatusInternalServerError
	ResponseCode[ErrStoringJWTToken] = http.StatusInternalServerError
	ResponseCode[ErrCreatingJWTToken] = http.StatusInternalServerError
	ResponseCode[ErrCreatingUser] = http.StatusInternalServerError
	ResponseCode[ErrUpdatingUser] = http.StatusInternalServerError
	ResponseCode[ErrUpdatingUserMetaData] = http.StatusInternalServerError
	ResponseCode[ErrResettingUserPassword] = http.StatusInternalServerError
	ResponseCode[ErrUpdatingUserPassword] = http.StatusInternalServerError
	ResponseCode[ErrUpdatingUserProfilePic] = http.StatusInternalServerError
	ResponseCode[ErrUpdatingUserStat] = http.StatusInternalServerError
	ResponseCode[ErrFetchingUsers] = http.StatusInternalServerError
	ResponseCode[ErrCountingUsers] = http.StatusInternalServerError
	ResponseCode[ErrUpdatingCacheUser] = http.StatusInternalServerError
	ResponseCode[ErrDeletingUser] = http.StatusInternalServerError
	ResponseCode[ErrResendingForgotPasswordOTP] = http.StatusInternalServerError
	ResponseCode[ErrCreatingForgotPasswordOTP] = http.StatusInternalServerError
	ResponseCode[ErrDeletingOldJWTToken] = http.StatusInternalServerError

	// Unauthorized
	ResponseCode[InvalidSigningMethod] = http.StatusUnauthorized
	ResponseCode[InvalidLoginAttemptHink] = http.StatusUnauthorized
	ResponseCode[InvalidLoginAttemptGoogle] = http.StatusUnauthorized
	ResponseCode[InvalidLoginAttemptFacebook] = http.StatusUnauthorized
	ResponseCode[InvalidLoginAttemptApple] = http.StatusUnauthorized
	ResponseCode[ErrParsingJWTToken] = http.StatusUnauthorized
	ResponseCode[NoLoggedInUserFound] = http.StatusUnauthorized
	ResponseCode[InvalidPassword] = http.StatusUnauthorized
	ResponseCode[InvalidAccessToken] = http.StatusUnauthorized
	ResponseCode[InvalidRefreshToken] = http.StatusUnauthorized
	ResponseCode[InvalidResetToken] = http.StatusUnauthorized
	ResponseCode[InvalidSocialLoginToken] = http.StatusUnauthorized
	ResponseCode[InvalidOTP] = http.StatusUnauthorized
	ResponseCode[InvalidOldToken] = http.StatusUnauthorized
	ResponseCode[InvalidOTPNonce] = http.StatusUnauthorized

	// Forbidden
	ResponseCode[AccessForbidden] = http.StatusForbidden

	// Status Not Found
	ResponseCode[UserNotFound] = http.StatusNotFound

}
