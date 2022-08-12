package controllers

import (
	"auth/errors"
	"auth/services"
	"auth/utils/messages"
	"fmt"
	"net/http"

	"auth/consts"

	"auth/types"
	"auth/utils/log"
	"auth/utils/methods"

	"github.com/labstack/echo/v4"
)

type AuthController struct {
	authService services.IAuthService
}

func NewAuthController(authService services.IAuthService) *AuthController {
	return &AuthController{
		authService: authService,
	}
}

func (ac *AuthController) Signup(c echo.Context) error {
	var req types.UserCreateUpdateReq
	var err error

	if err = c.Bind(&req); err != nil {
		log.Error(err)
		return c.JSON(messages.BuildResponseBy(errors.ParseRequest()))
	}

	req.ID = 0 // remove `id`(if provided somehow) while creation

	if err = req.Validate(); err != nil {
		log.Error(err)
		return c.JSON(messages.BuildValidationResponseBy(err, consts.User))
	}

	_, err = ac.authService.SignUp(&req)
	if err != nil {
		log.Error(err)
		return c.JSON(messages.BuildResponseBy(err))
	}

	return c.NoContent(http.StatusCreated)
}

func (ac *AuthController) Login(c echo.Context) error {
	var req types.LoginReq

	if err := c.Bind(&req); err != nil {
		log.Error(err)
		return c.JSON(messages.BuildResponseBy(errors.ParseRequest()))
	}

	if err := req.Validate(); err != nil {
		log.Error(err)
		return c.JSON(messages.BuildValidationResponseBy(err, consts.User))
	}

	res, err := ac.authService.Login(&req)
	if err != nil {
		log.Error(err)
		return c.JSON(messages.BuildResponseBy(err))
	}
	return c.JSON(http.StatusOK, res)
}

func (ac *AuthController) SocialLogin(c echo.Context) error {
	var req *types.SocialLoginReq

	if err := c.Bind(&req); err != nil {
		log.Error(err)
		return c.JSON(messages.BuildResponseBy(errors.ParseRequest()))
	}

	if err := req.Validate(); err != nil {
		log.Error(err)
		return c.JSON(messages.BuildValidationResponseBy(err, consts.User))
	}

	fmt.Println("====================================================")
	fmt.Println(req.LoginProvider)
	fmt.Println("====================================================")
	fmt.Println(req.Token)
	fmt.Println("====================================================")

	resp, err := ac.authService.SocialLogin(req)
	if err != nil {
		log.Error(err)
		return c.JSON(messages.BuildResponseBy(err))
	}

	return c.JSON(http.StatusOK, resp)
}

func (ac *AuthController) Logout(c echo.Context) error {
	var user *types.LoggedInUser
	var err error

	if user, err = GetUserFromContext(&c); err != nil {
		log.Error(err)
		return c.JSON(messages.BuildResponseBy(err))
	}

	if err := ac.authService.Logout(user); err != nil {
		log.Error(err)
		return c.JSON(messages.BuildResponseBy(errors.LogoutFailed()))
	}
	return c.NoContent(http.StatusOK)
}

func (ac *AuthController) RefreshToken(c echo.Context) error {
	var token types.TokenRefreshReq

	if err := c.Bind(&token); err != nil {
		log.Error(err)
		return c.JSON(messages.BuildResponseBy(err))
	}

	res, err := ac.authService.RefreshToken(token.RefreshToken)
	if err != nil {
		log.Error(err)
		return c.JSON(messages.BuildResponseBy(err))
	}
	return c.JSON(http.StatusOK, res)
}

func (ac *AuthController) VerifyToken(c echo.Context) error {
	accessToken, err := methods.AccessTokenFromHeader(c)
	if err != nil {
		log.Error(err)
		return c.JSON(messages.BuildResponseBy(err))
	}

	res, err := ac.authService.VerifyToken(accessToken)
	if err != nil {
		log.Error(err)
		return c.JSON(messages.BuildResponseBy(err))
	}

	return c.JSON(http.StatusOK, res)
}
