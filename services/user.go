package services

import (
	"auth/models"
	"auth/types"
)

type IUserService interface {
	CreateUser(userData interface{}) (*types.UserResp, error)
	UpdateUser(userData interface{}) (*types.UserResp, error)
	UpdateUserStat(userStat *types.UserStatUpdateReq) (*types.UserResp, error)
	UpdateUserCache(userId int) (*types.UserResp, error)
	UpdateLastLogin(userId int) error
	GetUserByEmail(email string) (*models.User, error)
	GetUserById(id int) (*models.User, error)
	GetUserFromCache(userId int, checkInCache bool) (*types.UserResp, error)
	GetUsers(pagination *types.Pagination) error
	DeleteUser(id int) error
	ChangePassword(userId int, req *types.ChangePasswordReq) error
	ForgotPassword(email string) (*types.ForgotPasswordResp, error)
	VerifyResetPassword(req *types.VerifyResetPasswordReq) error
	ResetPassword(req *types.ResetPasswordReq) error
	ResendForgotPasswordOtp(nonce string) (*types.ForgotPasswordOtpResp, error)
	CreateForgotPasswordOtp(userId int, email string) (*types.ForgotPasswordOtpResp, error)
	VerifyForgotPasswordOtp(data *types.ForgotPasswordOtpReq) (bool, error)
}
