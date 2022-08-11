package controllers

import (
	errors2 "auth/errors"
	"auth/utils/messages"
	"net/http"

	"auth/consts"

	"auth/services"
	"auth/types"
	"auth/utils/log"
	"github.com/labstack/echo/v4"
)

type UserController struct {
	userService *services.UserService
}

func NewUserController(userService *services.UserService) *UserController {
	return &UserController{
		userService: userService,
	}
}

func (uc *UserController) GetUser(c echo.Context) error {
	var user *types.LoggedInUser
	var err error
	if user, err = GetUserFromHeader(&c); err != nil {
		log.Error(err)
		return c.JSON(messages.BuildResponseBy(err))
	}
	res, err := uc.userService.GetUserResponse(user.ID, true)
	if err != nil {
		log.Error(err)
		return c.JSON(messages.BuildResponseBy(err))
	}
	return c.JSON(http.StatusOK, res)
}

func (uc *UserController) UpdateUser(c echo.Context) error {
	var req types.UserCreateUpdateReq
	var user *types.LoggedInUser
	var err error

	if user, err = GetUserFromHeader(&c); err != nil {
		log.Error(err)
		return c.JSON(messages.BuildResponseBy(err))
	}

	if err = c.Bind(&req); err != nil {
		log.Error(err)
		return c.JSON(messages.BuildResponseBy(errors2.ParseRequest()))
	}

	req.ID = user.ID
	if err = req.Validate(); err != nil {
		log.Error(err)
		return c.JSON(messages.BuildValidationResponseBy(err, consts.User))
	}

	userResp, err := uc.userService.Update(&req)
	if err != nil {
		log.Error(err)
		return c.JSON(messages.BuildResponseBy(err))
	}
	return c.JSON(http.StatusOK, userResp)
}

func (uc *UserController) UpdateProfilePic(c echo.Context) error {
	var req types.ProfilePicUpdateReq
	var user *types.LoggedInUser
	var err error

	if user, err = GetUserFromHeader(&c); err != nil {
		log.Error(err)
		return c.JSON(messages.BuildResponseBy(err))
	}

	if err = c.Bind(&req); err != nil {
		log.Error(err)
		return c.JSON(messages.BuildResponseBy(errors2.ParseRequest()))
	}

	req.ID = user.ID

	userResp, err := uc.userService.Update(&req)
	if err != nil {
		log.Error(err)
		return c.JSON(messages.BuildResponseBy(err))
	}

	return c.JSON(http.StatusOK, userResp)
}

func (uc *UserController) UpdateUserStat(c echo.Context) error {
	var req types.UserStatUpdateReq
	var user *types.LoggedInUser
	var err error

	if user, err = GetUserFromHeader(&c); err != nil {
		log.Error(err)
		return c.JSON(messages.BuildResponseBy(err))
	}

	if err = c.Bind(&req); err != nil {
		log.Error(err)
		return c.JSON(messages.BuildResponseBy(errors2.ParseRequest()))
	}

	req.ID = user.ID

	userResp, err := uc.userService.UpdateUserStat(&req)
	if err != nil {
		log.Error(err)
		return c.JSON(messages.BuildResponseBy(err))
	}

	return c.JSON(http.StatusOK, userResp)
}

func (uc *UserController) ChangePassword(c echo.Context) error {
	loggedInUser, err := GetUserFromContext(&c)
	if err != nil {
		log.Error(err)
		return c.JSON(messages.BuildResponseBy(err))
	}

	req := &types.ChangePasswordReq{}

	if err = c.Bind(&req); err != nil {
		log.Error(err)
		return c.JSON(messages.BuildResponseBy(errors2.ParseRequest()))
	}

	if err = req.Validate(); err != nil {
		log.Error(err)
		return c.JSON(messages.BuildValidationResponseBy(err, consts.User))
	}

	if req.OldPassword == req.NewPassword {
		return c.JSON(messages.BuildResponseBy(errors2.SamePassword()))
	}

	if err := uc.userService.ChangePassword(loggedInUser.ID, req); err != nil {
		log.Error(err)
		return c.JSON(messages.BuildResponseBy(err))
	}

	return c.NoContent(http.StatusOK)
}

func (uc *UserController) ForgotPassword(c echo.Context) error {
	req := &types.ForgotPasswordReq{}

	if err := c.Bind(&req); err != nil {
		log.Error(err)
		return c.JSON(messages.BuildResponseBy(errors2.ParseRequest()))
	}

	if err := req.Validate(); err != nil {
		log.Error(err)
		return c.JSON(messages.BuildValidationResponseBy(err, consts.User))
	}

	resp, err := uc.userService.ForgotPassword(req.Email)
	if err != nil {
		log.Error(err)
		return c.JSON(messages.BuildResponseBy(err))
	}

	return c.JSON(http.StatusOK, resp)
}

func (uc *UserController) VerifyResetPassword(c echo.Context) error {
	req := &types.VerifyResetPasswordReq{}

	if err := c.Bind(&req); err != nil {
		log.Error(err)
		return c.JSON(messages.BuildResponseBy(errors2.ParseRequest()))
	}

	if err := req.Validate(); err != nil {
		log.Error(err)
		return c.JSON(messages.BuildValidationResponseBy(err, consts.User))
	}

	if err := uc.userService.VerifyResetPassword(req); err != nil {
		log.Error(err)
		return c.JSON(messages.BuildResponseBy(err))
	}

	return c.NoContent(http.StatusOK)
}

func (uc *UserController) ResendForgotPasswordOtp(c echo.Context) error {
	req := &types.ForgotPasswordOtpResendReq{}

	if err := c.Bind(&req); err != nil {
		log.Error(err)
		return c.JSON(messages.BuildResponseBy(errors2.ParseRequest()))
	}

	if err := req.Validate(); err != nil {
		log.Error(err)
		return c.JSON(messages.BuildValidationResponseBy(err, consts.User))
	}

	res, err := uc.userService.ResendForgotPasswordOtp(req.Nonce)
	if err != nil {
		log.Error(err)
		return c.JSON(messages.BuildResponseBy(err))
	}

	return c.JSON(http.StatusCreated, res)
}

func (uc *UserController) ResetPassword(c echo.Context) error {
	req := &types.ResetPasswordReq{}

	if err := c.Bind(&req); err != nil {
		log.Error(err)
		return c.JSON(messages.BuildResponseBy(errors2.ParseRequest()))
	}

	if err := req.Validate(); err != nil {
		log.Error(err)
		return c.JSON(messages.BuildValidationResponseBy(err, consts.User))
	}

	verifyReq := &types.VerifyResetPasswordReq{
		Token: req.Token,
		ID:    req.ID,
	}

	if err := uc.userService.VerifyResetPassword(verifyReq); err != nil {
		log.Error(err)
		return c.JSON(messages.BuildResponseBy(err))
	}

	if err := uc.userService.ResetPassword(req); err != nil {
		log.Error(err)
		return c.JSON(messages.BuildResponseBy(err))
	}

	return c.NoContent(http.StatusOK)
}
