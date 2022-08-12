package services

import "auth/types"

type IOAuthService interface {
	CreateUserWithProvider(email, provider string) (int, error)

	ProcessGoogleLogin(token string) (int, error)
	ProcessFacebookLogin(token string) (int, error)
	ProcessAppleLogin(token string) (int, error)

	FetchGoogleUserInfo(idToken string) (*types.GoogleTokenInfo, error)
	FetchFbUserInfo(token string) (*types.FbTokenInfo, error)
	FetchAppleUserInfo(token string) (*types.AppleTokenInfo, error)

	IsValidGoogleIdToken(idToken string) bool
	IsValidAppleIdToken(idToken string) bool
}
