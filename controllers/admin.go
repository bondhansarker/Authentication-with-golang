package controllers

import (
	"errors"
	"net/http"
	"strconv"

	"auth/consts"
	"auth/rest_errors"
	"auth/services"
	"auth/utils/response"

	"auth/utils/log"
	"auth/utils/paginations"

	"auth/types"
	"auth/utils/methods"
	"github.com/labstack/echo/v4"
)

type AdminController struct {
	userService services.IUserService
}

func NewAdminController(userService services.IUserService) *AdminController {
	return &AdminController{
		userService: userService,
	}
}

func (ac *AdminController) FindUser(c echo.Context) error {
	checkAdminAuthorization(c)
	id, err := methods.ParseParam(c, "id")
	if err != nil {
		log.Error(err)
		return c.JSON(response.BuildResponseBy(err))
	}

	userId, err := strconv.Atoi(id)
	if err != nil {
		log.Error(err)
		return c.JSON(response.BuildResponseBy(errors.New(rest_errors.ErrParsingRequestBody)))
	}

	resp, err := ac.userService.GetUserFromCache(userId, true)
	if err != nil {
		log.Error(err)
		return c.JSON(response.BuildResponseBy(err))
	}

	return c.JSON(http.StatusOK, resp)
}

func (ac *AdminController) FindUsers(c echo.Context) error {
	checkAdminAuthorization(c)
	pagination := paginations.GeneratePaginationRequest(&c)
	err := ac.userService.GetUsers(pagination)
	if err != nil {
		log.Error(err)
		return c.JSON(response.BuildResponseBy(err))
	}
	resp := types.PaginationResp{}
	if err = methods.CopyStruct(pagination, &resp); err != nil {
		log.Error(err)
		return c.JSON(response.BuildResponseBy(err))
	}
	return c.JSON(http.StatusOK, resp)
}

func (ac *AdminController) UpdateUser(c echo.Context) error {
	checkAdminAuthorization(c)
	var req types.UserCreateUpdateReq
	if err := c.Bind(&req); err != nil {
		log.Error(err)
		return c.JSON(response.BuildResponseBy(errors.New(rest_errors.ErrParsingRequestBody)))
	}

	id, err := methods.ParseParam(c, "id")
	if err != nil {
		log.Error(err)
		return c.JSON(response.BuildResponseBy(err))
	}

	userId, err := strconv.Atoi(id)
	if err != nil {
		log.Error(err)
		return c.JSON(response.BuildResponseBy(errors.New(rest_errors.ErrParsingRequestBody)))
	}

	req.ID = userId

	if err = req.Validate(); err != nil {
		log.Error(err)
		return c.JSON(response.BuildValidationResponseBy(err, consts.User))
	}

	userResp, err := ac.userService.UpdateUser(&req)
	if err != nil {
		log.Error(err)
		return c.JSON(response.BuildResponseBy(err))
	}

	return c.JSON(http.StatusOK, userResp)
}

func (ac *AdminController) DeleteUser(c echo.Context) error {
	checkAdminAuthorization(c)
	var req types.UserDeleteReq
	if err := c.Bind(&req); err != nil {
		log.Error(err)
		return c.JSON(response.BuildResponseBy(errors.New(rest_errors.ErrParsingRequestBody)))

	}

	id, err := methods.ParseParam(c, "id")
	if err != nil {
		log.Error(err)
		return c.JSON(response.BuildResponseBy(err))
	}

	userId, err := strconv.Atoi(id)
	if err != nil {
		log.Error(err)
		return c.JSON(response.BuildResponseBy(errors.New(rest_errors.ErrParsingRequestBody)))
	}

	req.ID = userId

	if err := ac.userService.DeleteUser(&req); err != nil {
		log.Error(err)
		return c.JSON(response.BuildResponseBy(err))
	}

	return c.NoContent(http.StatusOK)
}

// private

func checkAdminAuthorization(c echo.Context) error {
	user, err := GetUserFromContext(&c)
	if err != nil {
		return c.JSON(response.BuildResponseBy(err))
	}
	if user.IsAdmin == nil || *user.IsAdmin == false {
		return c.JSON(response.BuildResponseBy(errors.New(rest_errors.AccessForbidden)))
	}
	return nil
}
