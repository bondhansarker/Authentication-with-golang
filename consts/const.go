package consts

const (
	AccessTokenType  = "access"
	RefreshTokenType = "refresh"

	LoginProviderFacebook = "facebook"
	LoginProviderGoogle   = "google"
	LoginProviderApple    = "apple"
	LoginProviderHink     = "hink"

	HeaderUserIdKey           = "hink-user-id"
	HeaderUserEmailAddressKey = "hink-user-email"
	HeaderIsAdminKey          = "hink-admin"

	// Domains
	User  = "user"
	Users = "users"

	// Reserved keywords
	ResetToken       = "reset token"
	VerifyToken      = "verify token"
	RefreshToken     = "refresh token"
	AccessToken      = "access token"
	JWTToken         = "jwt token"
	OldToken         = "old token"
	SocialLoginToken = "social login token"
	OTP              = "OTP"
	OTPNonce         = "OTP nonce"
	Password         = "password"
	MetaData         = "metadata"

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
