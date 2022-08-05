package controllers

import (
	"net/http"

	"auth/log"
	"auth/services"
	"auth/types"
	"auth/utils/errutil"
	"auth/utils/msgutil"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
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
	if user, err = uc.userService.GetUserFromHeader(&c); err != nil {
		log.Error(err)
		return c.JSON(http.StatusNotFound, msgutil.NoLoggedInUserMsg())
	}

	res, err := uc.userService.GetUserResponse(user.ID, true)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return c.JSON(http.StatusNotFound, msgutil.EntityNotFoundMsg("User"))
		}
		return c.JSON(http.StatusInternalServerError, msgutil.SomethingWentWrongMsg())
	}

	return c.JSON(http.StatusOK, res)
}

func (uc *UserController) UpdateUser(c echo.Context) error {
	var req types.UserCreateUpdateReq
	var user *types.LoggedInUser
	var err error

	if user, err = uc.userService.GetUserFromHeader(&c); err != nil {
		log.Error(err)
		return c.JSON(http.StatusNotFound, msgutil.NoLoggedInUserMsg())
	}

	if err = c.Bind(&req); err != nil {
		log.Error(err)
		return c.JSON(http.StatusBadRequest, msgutil.RequestBodyParseErrorResponseMsg())
	}

	req.ID = user.ID
	req.Verified = nil

	if err = req.Validate(); err != nil {
		return c.JSON(http.StatusBadRequest, &types.ValidationError{
			Message: msgutil.ValidationErrorMsg(),
			Error:   err,
		})
	}
	minimalUser, err := uc.userService.UpdateUser(&req)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return c.JSON(http.StatusNotFound, msgutil.EntityNotFoundMsg("User"))
		}
		return c.JSON(http.StatusInternalServerError, msgutil.SomethingWentWrongMsg())
	}

	return c.JSON(http.StatusOK, minimalUser)
}

func (uc *UserController) UpdateProfilePic(c echo.Context) error {
	var req types.ProfilePicUpdateReq
	var user *types.LoggedInUser
	var err error

	if user, err = uc.userService.GetUserFromHeader(&c); err != nil {
		log.Error(err)
		return c.JSON(http.StatusNotFound, msgutil.NoLoggedInUserMsg())
	}

	if err = c.Bind(&req); err != nil {
		log.Error(err)
		return c.JSON(http.StatusBadRequest, msgutil.RequestBodyParseErrorResponseMsg())
	}

	req.ID = user.ID

	minimalUser, err := uc.userService.UpdateProfilePic(&req)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return c.JSON(http.StatusNotFound, msgutil.EntityNotFoundMsg("User"))
		}
		return c.JSON(http.StatusInternalServerError, msgutil.SomethingWentWrongMsg())
	}

	return c.JSON(http.StatusOK, minimalUser)
}

func (uc *UserController) UpdateUserStat(c echo.Context) error {
	var req types.UserStatUpdateReq
	var user *types.LoggedInUser
	var err error

	if user, err = uc.userService.GetUserFromHeader(&c); err != nil {
		log.Error(err)
		return c.JSON(http.StatusNotFound, msgutil.NoLoggedInUserMsg())
	}

	if err = c.Bind(&req); err != nil {
		log.Error(err)
		return c.JSON(http.StatusBadRequest, msgutil.RequestBodyParseErrorResponseMsg())
	}

	req.ID = user.ID

	minimalUser, err := uc.userService.UpdateUserStat(&req)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return c.JSON(http.StatusNotFound, msgutil.EntityNotFoundMsg("User"))
		}
		return c.JSON(http.StatusInternalServerError, msgutil.SomethingWentWrongMsg())
	}

	return c.JSON(http.StatusOK, minimalUser)
}

func (uc *UserController) ChangePassword(c echo.Context) error {
	loggedInUser, err := uc.userService.GetUserFromContext(&c)
	if err != nil {
		log.Error(err)
		return c.JSON(http.StatusUnauthorized, msgutil.NoLoggedInUserMsg())
	}

	body := &types.ChangePasswordReq{}

	if err := c.Bind(&body); err != nil {
		log.Error(err)
		return c.JSON(http.StatusBadRequest, msgutil.RequestBodyParseErrorResponseMsg())
	}

	if err = body.Validate(); err != nil {
		return c.JSON(http.StatusBadRequest, &types.ValidationError{
			Message: msgutil.ValidationErrorMsg(),
			Error:   err,
		})
	}

	if body.OldPassword == body.NewPassword {
		return c.JSON(http.StatusBadRequest, msgutil.SamePasswordErrorMsg())
	}

	if err := uc.userService.ChangePassword(loggedInUser.ID, body); err != nil {
		switch err {
		case errutil.ErrInvalidPassword:
			return c.JSON(http.StatusBadRequest, msgutil.InvalidOldPasswordMsg())
		default:
			return c.JSON(http.StatusInternalServerError, msgutil.SomethingWentWrongMsg())
		}
	}

	return c.NoContent(http.StatusOK)
}

func (uc *UserController) ForgotPassword(c echo.Context) error {
	body := &types.ForgotPasswordReq{}

	if err := c.Bind(&body); err != nil {
		log.Error(err)
		return c.JSON(http.StatusBadRequest, msgutil.RequestBodyParseErrorResponseMsg())
	}

	if err := body.Validate(); err != nil {
		return c.JSON(http.StatusBadRequest, &types.ValidationError{
			Message: msgutil.ValidationErrorMsg(),
			Error:   err,
		})
	}

	resp, err := uc.userService.ForgotPassword(body.Email)
	if err != nil && err == gorm.ErrRecordNotFound {
		return c.JSON(http.StatusOK, map[string]interface{}{"message": msgutil.ForgotPasswordWithOtpMsg(body.Email)})
	}
	if err != nil && err == errutil.ErrSendingEmail {
		return c.JSON(http.StatusInternalServerError, msgutil.MailSendingFailedMsg("Password Reset"))
	}

	return c.JSON(http.StatusOK, resp)
}

func (uc *UserController) VerifyResetPassword(c echo.Context) error {
	req := &types.VerifyResetPasswordReq{}

	if err := c.Bind(&req); err != nil {
		log.Error(err)
		return c.JSON(http.StatusBadRequest, msgutil.RequestBodyParseErrorResponseMsg())
	}

	if err := req.Validate(); err != nil {
		return c.JSON(http.StatusBadRequest, &types.ValidationError{
			Message: msgutil.ValidationErrorMsg(),
			Error:   err,
		})
	}

	if err := uc.userService.VerifyResetPassword(req); err != nil {
		switch err {
		case errutil.ErrParseJwt,
			errutil.ErrInvalidPasswordResetToken:
			return c.JSON(http.StatusUnauthorized, msgutil.InvalidTokenMsg("reset_token"))
		case errutil.ErrInvalidOtpNonce:
			return c.JSON(http.StatusBadRequest, msgutil.InvalidTokenMsg("otp nonce"))
		case errutil.ErrInvalidOtp:
			return c.JSON(http.StatusBadRequest, msgutil.InvalidTokenMsg("otp"))
		case gorm.ErrRecordNotFound:
			return c.JSON(http.StatusUnauthorized, msgutil.EntityNotFoundMsg("user"))
		default:
			return c.JSON(http.StatusInternalServerError, msgutil.SomethingWentWrongMsg())
		}
	}

	return c.NoContent(http.StatusOK)
}

func (uc *UserController) ResendForgotPasswordOtp(c echo.Context) error {
	req := &types.ForgotPasswordOtpResendReq{}

	if err := c.Bind(&req); err != nil {
		log.Error(err)
		return c.JSON(http.StatusBadRequest, msgutil.RequestBodyParseErrorResponseMsg())
	}

	if err := req.Validate(); err != nil {
		return c.JSON(http.StatusBadRequest, &types.ValidationError{
			Message: msgutil.ValidationErrorMsg(),
			Error:   err,
		})
	}

	res, err := uc.userService.ResendForgotPasswordOtp(req.Nonce)
	if err != nil {
		switch err {
		case errutil.ErrInvalidOtpNonce:
			return c.JSON(http.StatusBadRequest, msgutil.InvalidTokenMsg("otp nonce"))
		case errutil.ErrInvalidOtp:
			return c.JSON(http.StatusBadRequest, msgutil.InvalidTokenMsg("otp"))
		default:
			return c.JSON(http.StatusInternalServerError, msgutil.SomethingWentWrongMsg())
		}
	}

	return c.JSON(http.StatusCreated, res)
}

func (uc *UserController) ResetPassword(c echo.Context) error {
	req := &types.ResetPasswordReq{}

	if err := c.Bind(&req); err != nil {
		log.Error(err)
		return c.JSON(http.StatusBadRequest, msgutil.RequestBodyParseErrorResponseMsg())
	}

	if err := req.Validate(); err != nil {
		return c.JSON(http.StatusBadRequest, &types.ValidationError{
			Message: msgutil.ValidationErrorMsg(),
			Error:   err,
		})
	}

	verifyReq := &types.VerifyResetPasswordReq{
		Token: req.Token,
		ID:    req.ID,
	}

	if err := uc.userService.VerifyResetPassword(verifyReq); err != nil {
		switch err {
		case errutil.ErrParseJwt,
			errutil.ErrInvalidPasswordResetToken:
			return c.JSON(http.StatusUnauthorized, msgutil.InvalidTokenMsg("reset_token"))
		case gorm.ErrRecordNotFound:
			return c.JSON(http.StatusUnauthorized, msgutil.EntityNotFoundMsg("user"))
		default:
			return c.JSON(http.StatusInternalServerError, msgutil.SomethingWentWrongMsg())
		}
	}

	if err := uc.userService.ResetPassword(req); err != nil {
		return c.JSON(http.StatusInternalServerError, msgutil.SomethingWentWrongMsg())
	}

	return c.NoContent(http.StatusOK)
}
