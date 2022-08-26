package services

import (
	"auth/types"
	"github.com/dgrijalva/jwt-go"
)

type IAuthService interface {
	SignUp(req *types.UserCreateUpdateReq) (*types.UserResp, error)
	Login(req *types.LoginReq) (*types.LoginResp, error)
	SocialLogin(req *types.SocialLoginReq) (*types.LoginResp, error)
	Logout(user *types.LoggedInUser) error
	CheckUserInCache(userId int, uuid, uuidType string) bool
	VerifyToken(accessToken string) (*types.UserResp, error)
	RefreshToken(refreshToken string) (*types.LoginResp, error)
	CreateToken(userId int) (*types.JwtToken, error)
	ParseToken(token, tokenType string) (*types.JwtToken, error)
	ParseTokenClaim(token, tokenType string) (jwt.MapClaims, error)
}
