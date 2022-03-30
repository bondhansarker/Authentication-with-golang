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
	return NewMessage().Set("message", "Failed to parse request body").Done()
}

func InvalidUserPassMsg() Data {
	return NewMessage().Set("message", "Invalid username or password").Done()
}

func JwtCreateErrorMsg() Data {
	return NewMessage().Set("message", "Failed to create JWT token").Done()
}

func JwtStoreErrorMsg() Data {
	return NewMessage().Set("message", "Failed to store JWT token uuid").Done()
}

func LogoutSuccessMsg() Data {
	return NewMessage().Set("message", "Successfully logged out").Done()
}

func LogoutFailedMsg() Data {
	return NewMessage().Set("message", "Failed to logout").Done()
}

func EntityCreationFailedMsg(entity string) Data {
	return NewMessage().Set("message", fmt.Sprintf("Failed to create %s", entity)).Done()
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
	return NewMessage().Set("message", "Something went wrong").Done()
}

func NoLoggedInUserMsg() Data {
	return NewMessage().Set("message", "No logged-in user found").Done()
}

func InvalidTokenMsg(tokenType string) Data {
	return NewMessage().Set("message", fmt.Sprintf("Invalid %s", tokenType)).Done()
}

func RefreshTokenCreateErrorMsg() Data {
	return NewMessage().Set("message", "Failed to create new JWT token").Done()
}

func AccessForbiddenMsg() Data {
	return NewMessage().Set("message", "Access forbidden").Done()
}

func ChangePasswordSuccessMsg() Data {
	return NewMessage().Set("message", "Password changed successfully").Done()
}

func ForgotPasswordMsg() Data {
	return NewMessage().Set("message", "Password reset link sent to email").Done()
}

func ForgotPasswordWithOtpMsg(email string) string {
	return fmt.Sprintf("OTP(One Time Password) for Password reset sent to the email %s if it is associated with Hink account.", email)
}

func SamePasswordErrorMsg() Data {
	return NewMessage().Set("message", "Password can't be same as old one").Done()
}

func VerifyResetPasswordMsg() Data {
	return NewMessage().Set("message", "Reset token & otp verified").Done()
}

func MailSendingFailedMsg(mailType string) Data {
	return NewMessage().Set("message", fmt.Sprintf("Failed to send %s email", mailType)).Done()
}

func PasswordResetSuccessMsg() Data {
	return NewMessage().Set("message", "Password reset success").Done()
}

func LoggedInUserDeleteMsg() Data {
	return NewMessage().Set("message", "Cannot delete self").Done()
}

func InvalidOldPasswordMsg() Data {
	return NewMessage().Set("message", "Old password didn't match").Done()
}

func InvalidLoginAttemptMsg(provider string) Data {
	return NewMessage().Set("message", fmt.Sprintf("Registered via %s", provider)).Done()
}

func UserAlreadyRegisteredMsg() Data {
	return NewMessage().Set("message", "User already registered.").Done()
}

func UserAlreadyRegisteredViaSocialMsg(platform string) Data {
	return NewMessage().Set("message", fmt.Sprintf("User already registered via %s", platform)).Done()
}

func InvalidLoginTokenMsg() Data {
	return NewMessage().Set("message", "Invalid login token.").Done()
}

func SocialLoginFailedMsg() Data {
	return NewMessage().Set("message", "Failed social login.").Done()
}
