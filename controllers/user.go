package controllers

import (
	"net/http"
	"strconv"

	"auth/log"
	"auth/services/usersvc"
	"auth/types"
	"auth/utils/errutil"
	"auth/utils/methodutil"
	"auth/utils/msgutil"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
)

func GetUser(c echo.Context) error {
	var user *types.LoggedInUser
	var err error

	if user, err = usersvc.GetUserFromHeader(c); err != nil {
		log.Error(err)
		return c.JSON(http.StatusNotFound, msgutil.NoLoggedInUserMsg())
	}

	res, err := usersvc.GetUser(user.ID)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return c.JSON(http.StatusNotFound, msgutil.EntityNotFoundMsg("User"))
		}
		return c.JSON(http.StatusInternalServerError, msgutil.SomethingWentWrongMsg())
	}

	return c.JSON(http.StatusOK, res)
}

func User(c echo.Context) error {
	var err error
	if _, err = usersvc.GetUserFromHeader(c); err != nil {
		log.Error(err)
		return c.JSON(http.StatusNotFound, msgutil.NoLoggedInUserMsg())
	}

	id, parseErr := methodutil.ParseParam(c, "id")
	if parseErr != nil {
		log.Error(parseErr)
		return c.JSON(http.StatusBadRequest, parseErr)
	}
	userId, err := strconv.Atoi(id)
	if err != nil {
		log.Error(parseErr)
		return c.JSON(http.StatusBadRequest, parseErr)
	}

	res, err := usersvc.GetUser(userId)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return c.JSON(http.StatusNotFound, msgutil.EntityNotFoundMsg("User"))
		}
		return c.JSON(http.StatusInternalServerError, msgutil.SomethingWentWrongMsg())
	}

	return c.JSON(http.StatusOK, res)
}

func Users(c echo.Context) error {
	if _, err := usersvc.GetUserFromHeader(c); err != nil {
		log.Error(err)
		return c.JSON(http.StatusInternalServerError, msgutil.NoLoggedInUserMsg())
	}
	pagination := GeneratePaginationRequest(c)
	err := usersvc.GetUsers(pagination)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return c.JSON(http.StatusNotFound, msgutil.EntityNotFoundMsg("User"))
		}
		return c.JSON(http.StatusInternalServerError, msgutil.SomethingWentWrongMsg())
	}
	resp := types.PaginationResp{}
	if err = methodutil.CopyStruct(pagination, &resp); err != nil {
		log.Error(err)
		return c.JSON(http.StatusInternalServerError, msgutil.SomethingWentWrongMsg())
	}
	return c.JSON(http.StatusOK, resp)
}

func UpdateUser(c echo.Context) error {
	var req types.UserCreateUpdateReq
	var user *types.LoggedInUser
	var err error

	if user, err = usersvc.GetUserFromHeader(c); err != nil {
		log.Error(err)
		return c.JSON(http.StatusInternalServerError, msgutil.NoLoggedInUserMsg())
	}

	if err = c.Bind(&req); err != nil {
		log.Error(err)
		return c.JSON(http.StatusBadRequest, msgutil.RequestBodyParseErrorResponseMsg())
	}

	req.ID = user.ID
	req.Verified = nil

	if err = req.Validate(); err != nil {
		return c.JSON(http.StatusBadRequest, &types.ValidationError{
			Message: "failed to validate fields",
			Error:   err,
		})
	}
	minimalUser, err := usersvc.UpdateUser(&req)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return c.JSON(http.StatusNotFound, msgutil.EntityNotFoundMsg("User"))
		}
		return c.JSON(http.StatusInternalServerError, msgutil.SomethingWentWrongMsg())
	}

	return c.JSON(http.StatusOK, minimalUser)
}

func Update(c echo.Context) error {
	var req types.UserCreateUpdateReq
	var err error

	if _, err = usersvc.GetUserFromHeader(c); err != nil {
		log.Error(err)
		return c.JSON(http.StatusNotFound, msgutil.NoLoggedInUserMsg())
	}

	if err = c.Bind(&req); err != nil {
		log.Error(err)
		return c.JSON(http.StatusBadRequest, msgutil.RequestBodyParseErrorResponseMsg())
	}

	id, parseErr := methodutil.ParseParam(c, "id")
	if parseErr != nil {
		log.Error(parseErr)
		return c.JSON(http.StatusBadRequest, parseErr)
	}
	userId, err := strconv.Atoi(id)
	if err != nil {
		log.Error(parseErr)
		return c.JSON(http.StatusBadRequest, parseErr)
	}

	req.ID = userId

	if err = req.Validate(); err != nil {
		return c.JSON(http.StatusBadRequest, &types.ValidationError{
			Error:   err,
			Message: "failed to validate fields",
		})
	}
	minimalUser, err := usersvc.UpdateUser(&req)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return c.JSON(http.StatusNotFound, msgutil.EntityNotFoundMsg("User"))
		}
		return c.JSON(http.StatusInternalServerError, msgutil.SomethingWentWrongMsg())
	}

	return c.JSON(http.StatusOK, minimalUser)
}

func UpdateProfilePic(c echo.Context) error {
	var req types.ProfilePicUpdateReq
	var user *types.LoggedInUser
	var err error

	if user, err = usersvc.GetUserFromHeader(c); err != nil {
		log.Error(err)
		return c.JSON(http.StatusInternalServerError, msgutil.NoLoggedInUserMsg())
	}

	if err = c.Bind(&req); err != nil {
		log.Error(err)
		return c.JSON(http.StatusBadRequest, msgutil.RequestBodyParseErrorResponseMsg())
	}

	req.ID = user.ID

	minimalUser, err := usersvc.UpdateProfilePic(&req)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return c.JSON(http.StatusNotFound, msgutil.EntityNotFoundMsg("User"))
		}
		return c.JSON(http.StatusInternalServerError, msgutil.SomethingWentWrongMsg())
	}

	return c.JSON(http.StatusOK, minimalUser)
}

func UpdateUserStat(c echo.Context) error {
	var req types.UserStatUpdateReq
	var user *types.LoggedInUser
	var err error

	if user, err = usersvc.GetUserFromHeader(c); err != nil {
		log.Error(err)
		return c.JSON(http.StatusInternalServerError, msgutil.NoLoggedInUserMsg())
	}

	if err = c.Bind(&req); err != nil {
		log.Error(err)
		return c.JSON(http.StatusBadRequest, msgutil.RequestBodyParseErrorResponseMsg())
	}

	req.ID = user.ID

	minimalUser, err := usersvc.UpdateUserStat(&req)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return c.JSON(http.StatusNotFound, msgutil.EntityNotFoundMsg("User"))
		}
		return c.JSON(http.StatusInternalServerError, msgutil.SomethingWentWrongMsg())
	}

	return c.JSON(http.StatusOK, minimalUser)
}

func ChangePassword(c echo.Context) error {
	loggedInUser, err := usersvc.GetUserFromContext(c)
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
			Message: "failed to validate fields",
			Error:   err,
		})
	}

	if body.OldPassword == body.NewPassword {
		return c.JSON(http.StatusBadRequest, msgutil.SamePasswordErrorMsg())
	}

	if err := usersvc.ChangePassword(loggedInUser.ID, body); err != nil {
		switch err {
		case errutil.ErrInvalidPassword:
			return c.JSON(http.StatusBadRequest, msgutil.InvalidOldPasswordMsg())
		default:
			return c.JSON(http.StatusInternalServerError, msgutil.SomethingWentWrongMsg())
		}
	}

	return c.NoContent(http.StatusOK)
}

func ForgotPassword(c echo.Context) error {
	body := &types.ForgotPasswordReq{}

	if err := c.Bind(&body); err != nil {
		log.Error(err)
		return c.JSON(http.StatusBadRequest, msgutil.RequestBodyParseErrorResponseMsg())
	}

	if err := body.Validate(); err != nil {
		return c.JSON(http.StatusBadRequest, &types.ValidationError{
			Message: "failed to validate fields",
			Error:   err,
		})
	}

	resp, err := usersvc.ForgotPassword(body.Email)
	if err != nil && err == gorm.ErrRecordNotFound {
		return c.JSON(http.StatusOK, map[string]interface{}{"message": msgutil.ForgotPasswordWithOtpMsg(body.Email)})
	}
	if err != nil && err == errutil.ErrSendingEmail {
		return c.JSON(http.StatusInternalServerError, msgutil.MailSendingFailedMsg("Password Reset"))
	}

	return c.JSON(http.StatusOK, resp)
}

func VerifyResetPassword(c echo.Context) error {
	req := &types.VerifyResetPasswordReq{}

	if err := c.Bind(&req); err != nil {
		log.Error(err)
		return c.JSON(http.StatusBadRequest, msgutil.RequestBodyParseErrorResponseMsg())
	}

	if err := req.Validate(); err != nil {
		return c.JSON(http.StatusBadRequest, &types.ValidationError{
			Message: "failed to validate fields",
			Error:   err,
		})
	}

	if err := usersvc.VerifyResetPassword(req); err != nil {
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

func ResendForgotPasswordOtp(c echo.Context) error {
	req := &types.ForgotPasswordOtpResendReq{}

	if err := c.Bind(&req); err != nil {
		log.Error(err)
		return c.JSON(http.StatusBadRequest, msgutil.RequestBodyParseErrorResponseMsg())
	}

	if err := req.Validate(); err != nil {
		return c.JSON(http.StatusBadRequest, &types.ValidationError{
			Message: "failed to validate fields",
			Error:   err,
		})
	}

	res, err := usersvc.ResendForgotPasswordOtp(req.Nonce)
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

func ResetPassword(c echo.Context) error {
	req := &types.ResetPasswordReq{}

	if err := c.Bind(&req); err != nil {
		log.Error(err)
		return c.JSON(http.StatusBadRequest, msgutil.RequestBodyParseErrorResponseMsg())
	}

	if err := req.Validate(); err != nil {
		return c.JSON(http.StatusBadRequest, &types.ValidationError{
			Message: "failed to validate fields",
			Error:   err,
		})
	}

	verifyReq := &types.VerifyResetPasswordReq{
		Token: req.Token,
		ID:    req.ID,
	}

	if err := usersvc.VerifyResetPassword(verifyReq); err != nil {
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

	if err := usersvc.ResetPassword(req); err != nil {
		return c.JSON(http.StatusInternalServerError, msgutil.SomethingWentWrongMsg())
	}

	return c.NoContent(http.StatusOK)
}
