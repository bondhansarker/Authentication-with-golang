package controllers

import (
	"fmt"
	"net/http"

	"auth/log"
	"auth/services"
	"auth/types"
	"auth/utils/errutil"
	"auth/utils/methodutil"
	"auth/utils/msgutil"

	"github.com/labstack/echo/v4"
)

type AuthController struct {
	userService *services.UserService
	authService *services.AuthService
}

func NewAuthController(userService *services.UserService, authService *services.AuthService) *AuthController {
	return &AuthController{
		userService: userService,
		authService: authService,
	}
}

func (ac *AuthController) Signup(c echo.Context) error {
	var req types.UserCreateUpdateReq
	var err error

	if err = c.Bind(&req); err != nil {
		log.Error(err)
		return c.JSON(http.StatusBadRequest, msgutil.RequestBodyParseErrorResponseMsg())
	}

	req.ID = 0 // remove `id`(if provided somehow) while creation
	req.Verified = nil

	if err = req.Validate(); err != nil {
		return c.JSON(http.StatusBadRequest, &types.ValidationError{
			Message: msgutil.ValidationErrorMsg(),
			Error:   err,
		})
	}

	err = ac.userService.CreateUser(&req)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, msgutil.EntityCreationFailedMsg("User"))
	}

	return c.NoContent(http.StatusCreated)
}

func (ac *AuthController) Login(c echo.Context) error {
	var cred types.LoginReq
	var res *types.LoginResp
	var err error

	if err = c.Bind(&cred); err != nil {
		log.Error(err)
		return c.JSON(http.StatusBadRequest, msgutil.RequestBodyParseErrorResponseMsg())
	}

	if err = cred.Validate(); err != nil {
		return c.JSON(http.StatusBadRequest, &types.ValidationError{
			Message: msgutil.ValidationErrorMsg(),
			Error:   err,
		})
	}

	if res, err = ac.authService.Login(&cred); err != nil {
		switch err {
		case errutil.ErrInvalidEmail, errutil.ErrInvalidPassword:
			return c.JSON(http.StatusUnauthorized, msgutil.InvalidUserPassMsg())
		case errutil.ErrLoginAttemptWithAppleProvider:
			return c.JSON(http.StatusUnprocessableEntity, msgutil.InvalidLoginAttemptMsg("Apple"))
		case errutil.ErrLoginAttemptWithGoogleProvider:
			return c.JSON(http.StatusUnprocessableEntity, msgutil.InvalidLoginAttemptMsg("Google"))
		case errutil.ErrLoginAttemptWithFacebookProvider:
			return c.JSON(http.StatusUnprocessableEntity, msgutil.InvalidLoginAttemptMsg("Facebook"))
		case errutil.ErrCreateJwt:
			return c.JSON(http.StatusInternalServerError, msgutil.JwtCreateErrorMsg())
		case errutil.ErrStoreTokenUuid:
			return c.JSON(http.StatusInternalServerError, msgutil.JwtStoreErrorMsg())
		default:
			return c.JSON(http.StatusInternalServerError, msgutil.SomethingWentWrongMsg())
		}
	}

	return c.JSON(http.StatusOK, res)
}

func (ac *AuthController) Logout(c echo.Context) error {
	var user *types.LoggedInUser
	var err error

	if user, err = ac.userService.GetUserFromContext(&c); err != nil {
		log.Error(err)
		return c.JSON(http.StatusInternalServerError, msgutil.NoLoggedInUserMsg())
	}

	if err := ac.authService.Logout(user); err != nil {
		log.Error(err)
		return c.JSON(http.StatusInternalServerError, msgutil.LogoutFailedMsg())
	}

	return c.NoContent(http.StatusOK)
}

func (ac *AuthController) SocialLogin(c echo.Context) error {
	var req *types.SocialLoginReq
	var err error

	if err = c.Bind(&req); err != nil {
		log.Error(err)
		return c.JSON(http.StatusBadRequest, msgutil.RequestBodyParseErrorResponseMsg())
	}

	if err = req.Validate(); err != nil {
		log.Error(err.Error())
		return c.JSON(http.StatusBadRequest, &types.ValidationError{
			Message: msgutil.ValidationErrorMsg(),
			Error:   err,
		})
	}

	fmt.Println("====================================================")
	fmt.Println(req.Token, req.LoginProvider)
	fmt.Println("====================================================")

	resp, err := ac.authService.SocialLogin(req)
	if err != nil {
		switch err {
		case errutil.ErrInvalidLoginToken:
			return c.JSON(http.StatusUnauthorized, msgutil.InvalidLoginTokenMsg())
		case errutil.ErrEmailAlreadyRegistered:
			return c.JSON(http.StatusUnprocessableEntity, msgutil.UserAlreadyRegisteredMsg())
		case errutil.ErrUserAlreadyRegisteredViaGoogle:
			return c.JSON(http.StatusUnprocessableEntity, msgutil.UserAlreadyRegisteredViaSocialMsg("Google"))
		case errutil.ErrUserAlreadyRegisteredViaFacebook:
			return c.JSON(http.StatusUnprocessableEntity, msgutil.UserAlreadyRegisteredViaSocialMsg("Facebook"))
		case errutil.ErrUserAlreadyRegisteredViaApple:
			return c.JSON(http.StatusUnprocessableEntity, msgutil.UserAlreadyRegisteredViaSocialMsg("Apple"))
		case errutil.ErrCreateJwt:
			return c.JSON(http.StatusInternalServerError, msgutil.JwtCreateErrorMsg())
		case errutil.ErrStoreTokenUuid:
			return c.JSON(http.StatusInternalServerError, msgutil.JwtStoreErrorMsg())
		default:
			return c.JSON(http.StatusInternalServerError, msgutil.SocialLoginFailedMsg())
		}
	}

	return c.JSON(http.StatusOK, resp)
}

func (ac *AuthController) RefreshToken(c echo.Context) error {
	var token types.TokenRefreshReq
	var res *types.LoginResp
	var err error

	if err = c.Bind(&token); err != nil {
		log.Error(err)
		return c.JSON(http.StatusBadRequest, msgutil.RequestBodyParseErrorResponseMsg())
	}

	if res, err = ac.authService.RefreshToken(token.RefreshToken); err != nil {
		switch err {
		case errutil.ErrParseJwt,
			errutil.ErrInvalidRefreshToken,
			errutil.ErrInvalidRefreshUuid:
			return c.JSON(http.StatusUnauthorized, msgutil.InvalidTokenMsg("refresh_token"))
		case errutil.ErrCreateJwt:
			return c.JSON(http.StatusInternalServerError, msgutil.RefreshTokenCreateErrorMsg())
		default:
			return c.JSON(http.StatusInternalServerError, msgutil.SomethingWentWrongMsg())
		}
	}

	return c.JSON(http.StatusOK, res)
}

func (ac *AuthController) VerifyToken(c echo.Context) error {
	accessToken, err := methodutil.AccessTokenFromHeader(c)

	if err != nil {
		return c.JSON(http.StatusUnauthorized, msgutil.InvalidTokenMsg("access_token"))
	}

	res, err := ac.authService.VerifyToken(accessToken)
	if err != nil {
		switch err {
		case errutil.ErrParseJwt,
			errutil.ErrInvalidAccessToken,
			errutil.ErrInvalidAccessUuid:
			return c.JSON(http.StatusUnauthorized, msgutil.InvalidTokenMsg("access_token"))
		default:
			return c.JSON(http.StatusInternalServerError, msgutil.SomethingWentWrongMsg())
		}
	}

	return c.JSON(http.StatusOK, res)
}
