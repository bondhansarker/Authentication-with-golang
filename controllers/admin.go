package controllers

import (
	"net/http"
	"strconv"

	"auth/config"
	"auth/services"
	"auth/types"
	"auth/utils/methodutil"
	"auth/utils/msgutil"
	"github.com/labstack/echo/v4"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type AdminController struct {
	config      *config.Config
	userService *services.UserService
}

func NewAdminController(userService *services.UserService) *AdminController {
	return &AdminController{
		config:      config.GetConfig(),
		userService: userService,
	}
}

func (ac *AdminController) User(c echo.Context) error {
	isAdmin, err := ac.userService.IsAdmin(&c)
	if err != nil {
		log.Error(err)
		return c.JSON(http.StatusNotFound, msgutil.NoLoggedInUserMsg())
	}
	if isAdmin != true {
		return c.JSON(http.StatusForbidden, msgutil.NoAccessMsg())
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

	res, err := ac.userService.GetUserResponse(userId, true)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return c.JSON(http.StatusNotFound, msgutil.EntityNotFoundMsg("User"))
		}
		return c.JSON(http.StatusInternalServerError, msgutil.SomethingWentWrongMsg())
	}

	return c.JSON(http.StatusOK, res)
}

func (ac *AdminController) Users(c echo.Context) error {
	isAdmin, err := ac.userService.IsAdmin(&c)
	if err != nil {
		log.Error(err)
		return c.JSON(http.StatusNotFound, msgutil.NoLoggedInUserMsg())
	}
	if isAdmin != true {
		return c.JSON(http.StatusForbidden, msgutil.NoAccessMsg())
	}
	pagination := GeneratePaginationRequest(&c, ac.config)
	err = ac.userService.GetUsers(pagination)
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

func (ac *AdminController) Update(c echo.Context) error {
	var req types.UserCreateUpdateReq
	isAdmin, err := ac.userService.IsAdmin(&c)
	if err != nil {
		log.Error(err)
		return c.JSON(http.StatusNotFound, msgutil.NoLoggedInUserMsg())
	}
	if isAdmin != true {
		return c.JSON(http.StatusForbidden, msgutil.NoAccessMsg())
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
			Message: msgutil.ValidationErrorMsg(),
		})
	}
	minimalUser, err := ac.userService.UpdateUser(&req)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return c.JSON(http.StatusNotFound, msgutil.EntityNotFoundMsg("User"))
		}
		return c.JSON(http.StatusInternalServerError, msgutil.SomethingWentWrongMsg())
	}

	return c.JSON(http.StatusOK, minimalUser)
}
