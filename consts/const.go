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

	// Model keywords
	User  = "user"
	Users = "users"

	// Reserved keywords
	Token                 = "token"
	ResetToken            = "reset token"
	RefreshToken          = "refresh token"
	AccessToken           = "access token"
	JWTToken              = "jwt token"
	OldToken              = "old token"
	SocialLoginToken      = "social login token"
	OTP                   = "OTP"
	OTPNonce              = "OTP nonce"
	Password              = "password"
	ProfilePic            = "profile picture"
	Stat                  = "user statistics"
	MetaData              = "metadata"
	UserForgotPasswordOtp = "forgot_"

	// default values
	DefaultInt = 0
)

func LoginProviders() map[string]bool {
	return map[string]bool{
		LoginProviderHink:     true,
		LoginProviderFacebook: true,
		LoginProviderGoogle:   true,
		LoginProviderApple:    true,
	}
}
