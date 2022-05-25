package consts

const (
	AccessTokenType  = "access"
	RefreshTokenType = "refresh"

	LoginProviderFacebook = "facebook"
	LoginProviderGoogle   = "google"
	LoginProviderApple    = "apple"
	LoginProviderHink     = "hink"

	UserIDHeader = "hink-user-id"

	Hink     = "Hink"
	Facebook = "Facebook"
	Google   = "Google"
	Apple    = "Apple"

	UserCreateMailApiPath            = "consumer/user-create"
	UserForgotPasswordWithOtpApiPath = "forgot-password/otp"

	UserForgotPasswordOtp = "forgot_"
)

func LoginProviders() map[string]string {
	return map[string]string{
		LoginProviderHink:     Hink,
		LoginProviderFacebook: Facebook,
		LoginProviderGoogle:   Google,
		LoginProviderApple:    Apple,
	}
}
