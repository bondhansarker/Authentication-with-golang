package controllers

import (
	errors2 "auth/errors"
	"auth/utils/messages"
	"net/http"
	"strconv"

	"auth/consts"

	"auth/utils/log"
	"auth/utils/paginations"

	"auth/services"
	"auth/types"
	"auth/utils/methods"
	"github.com/labstack/echo/v4"
)

type AdminController struct {
	userService *services.UserService
}

func NewAdminController(userService *services.UserService) *AdminController {
	return &AdminController{
		userService: userService,
	}
}

func CheckAdminAuthorization(c echo.Context) error {
	user, err := GetUserFromContext(&c)
	if err != nil {
		return c.JSON(messages.BuildResponseBy(err))
	}
	if user.IsAdmin == nil || *user.IsAdmin == false {
		err = errors2.AccessForbidden()
		return c.JSON(messages.BuildResponseBy(err))
	}
	return nil
}

func (ac *AdminController) FindUser(c echo.Context) error {
	CheckAdminAuthorization(c)
	id, err := methods.ParseParam(c, "id")
	if err != nil {
		log.Error(err)
		return c.JSON(messages.BuildResponseBy(err))
	}

	userId, err := strconv.Atoi(id)
	if err != nil {
		log.Error(err)
		return c.JSON(messages.BuildResponseBy(errors2.ParseRequest()))
	}

	resp, err := ac.userService.GetUserResponse(userId, true)
	if err != nil {
		log.Error(err)
		return c.JSON(messages.BuildResponseBy(err))
	}

	return c.JSON(http.StatusOK, resp)
}

func (ac *AdminController) FindUsers(c echo.Context) error {
	CheckAdminAuthorization(c)
	pagination := paginations.GeneratePaginationRequest(&c)
	err := ac.userService.GetUsers(pagination)
	if err != nil {
		log.Error(err)
		return c.JSON(messages.BuildResponseBy(err))
	}
	resp := types.PaginationResp{}
	if err = methods.CopyStruct(pagination, &resp); err != nil {
		log.Error(err)
		return c.JSON(messages.BuildResponseBy(err))
	}
	return c.JSON(http.StatusOK, resp)
}

func (ac *AdminController) UpdateUser(c echo.Context) error {
	CheckAdminAuthorization(c)
	var req types.UserCreateUpdateReq
	if err := c.Bind(&req); err != nil {
		log.Error(err)
		return c.JSON(messages.BuildResponseBy(errors2.ParseRequest()))
	}

	id, err := methods.ParseParam(c, "id")
	if err != nil {
		log.Error(err)
		return c.JSON(messages.BuildResponseBy(err))
	}

	userId, err := strconv.Atoi(id)
	if err != nil {
		log.Error(err)
		return c.JSON(messages.BuildResponseBy(errors2.ParseRequest()))
	}

	req.ID = userId

	if err = req.Validate(); err != nil {
		log.Error(err)
		return c.JSON(messages.BuildValidationResponseBy(err, consts.User))
	}

	resp, err := ac.userService.Update(&req)
	if err != nil {
		log.Error(err)
		return c.JSON(messages.BuildResponseBy(err))
	}

	return c.JSON(http.StatusOK, resp)
}
