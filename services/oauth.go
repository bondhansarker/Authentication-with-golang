package services

import "auth/types"

type IOAuthService interface {
	ProcessGoogleLogin(token string) (int, error)
	ProcessFacebookLogin(token string) (int, error)
	ProcessAppleLogin(token string) (int, error)

	FetchFbUserInfo(token string) (*types.FbTokenInfo, error)
	FetchGoogleUserInfo(idToken string) (*types.GoogleTokenInfo, error)
	FetchAppleUserInfo(token string) (*types.AppleTokenInfo, error)
}
