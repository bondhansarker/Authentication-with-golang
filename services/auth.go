package services

import (
	"auth/types"
)

type IAuthService interface {
	SignUp(req *types.UserCreateUpdateReq) (*types.UserResp, error)
	Login(req *types.LoginReq) (*types.LoginResp, error)
	SocialLogin(req *types.SocialLoginReq) (*types.LoginResp, error)
	Logout(user *types.LoggedInUser) error
	VerifyToken(accessToken string) (*types.UserResp, error)
	RefreshToken(refreshToken string) (*types.LoginResp, error)
}
