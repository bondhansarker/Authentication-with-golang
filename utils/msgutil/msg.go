package msgutil

import (
	"fmt"
)

type Data map[string]interface{}

type Msg struct {
	Data Data
}

func NewMessage() Msg {
	return Msg{
		Data: make(Data),
	}
}

func (m Msg) Set(key string, value interface{}) Msg {
	m.Data[key] = value
	return m
}

func (m Msg) Done() Data {
	return m.Data
}

func RequestBodyParseErrorResponseMsg() Data {
	return NewMessage().Set("message", "failed to parse request body").Done()
}

func InvalidUserPassMsg() Data {
	return NewMessage().Set("message", "invalid username or password").Done()
}

func JwtCreateErrorMsg() Data {
	return NewMessage().Set("message", "failed to create JWT token").Done()
}

func JwtStoreErrorMsg() Data {
	return NewMessage().Set("message", "failed to store JWT token uuid").Done()
}

func LogoutSuccessMsg() Data {
	return NewMessage().Set("message", "successfully logged out").Done()
}

func LogoutFailedMsg() Data {
	return NewMessage().Set("message", "failed to logout").Done()
}

func EntityCreationFailedMsg(entity string) Data {
	return NewMessage().Set("message", fmt.Sprintf("failed to create %s", entity)).Done()
}

func EntityNotFoundMsg(entity string) Data {
	return NewMessage().Set("message", fmt.Sprintf("%s not found", entity)).Done()
}

func EntityUpdateSuccessMsg(entity string) Data {
	return NewMessage().Set("message", fmt.Sprintf("%s updated successfully", entity)).Done()
}

func EntityDeleteSuccessMsg(entity string) Data {
	return NewMessage().Set("message", fmt.Sprintf("%s deleted successfully", entity)).Done()
}

func SomethingWentWrongMsg() Data {
	return NewMessage().Set("message", "something went wrong").Done()
}

func NoLoggedInUserMsg() Data {
	return NewMessage().Set("message", "no logged-in user found").Done()
}

func NoAccessMsg() Data {
	return NewMessage().Set("message", "access denied for this user").Done()
}

func InvalidTokenMsg(tokenType string) Data {
	return NewMessage().Set("message", fmt.Sprintf("invalid %s", tokenType)).Done()
}

func RefreshTokenCreateErrorMsg() Data {
	return NewMessage().Set("message", "failed to create new JWT token").Done()
}

func AccessForbiddenMsg() Data {
	return NewMessage().Set("message", "access forbidden").Done()
}

func ChangePasswordSuccessMsg() Data {
	return NewMessage().Set("message", "password changed successfully").Done()
}

func ForgotPasswordMsg() Data {
	return NewMessage().Set("message", "password reset link sent to email").Done()
}

func ForgotPasswordWithOtpMsg(email string) string {
	return fmt.Sprintf("otp(One Time Password) for Password reset sent to the email %s if it is associated with Hink account.", email)
}

func SamePasswordErrorMsg() Data {
	return NewMessage().Set("message", "password can't be same as old one").Done()
}

func VerifyResetPasswordMsg() Data {
	return NewMessage().Set("message", "reset token & otp verified").Done()
}

func MailSendingFailedMsg(mailType string) Data {
	return NewMessage().Set("message", fmt.Sprintf("failed to send %s email", mailType)).Done()
}

func PasswordResetSuccessMsg() Data {
	return NewMessage().Set("message", "password reset success").Done()
}

func LoggedInUserDeleteMsg() Data {
	return NewMessage().Set("message", "cannot delete self").Done()
}

func InvalidOldPasswordMsg() Data {
	return NewMessage().Set("message", "old password didn't match").Done()
}

func InvalidLoginAttemptMsg(provider string) Data {
	return NewMessage().Set("message", fmt.Sprintf("registered via %s", provider)).Done()
}

func UserAlreadyRegisteredMsg() Data {
	return NewMessage().Set("message", "user already registered.").Done()
}

func UserAlreadyRegisteredViaSocialMsg(platform string) Data {
	return NewMessage().Set("message", fmt.Sprintf("user already registered via %s", platform)).Done()
}

func InvalidLoginTokenMsg() Data {
	return NewMessage().Set("message", "invalid login token.").Done()
}

func SocialLoginFailedMsg() Data {
	return NewMessage().Set("message", "failed social login.").Done()
}

func ValidationErrorMsg() string {
	return "failed to validate fields"
}
