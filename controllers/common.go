package controllers

import (
	errors2 "auth/errors"
	"strconv"

	"auth/consts"
	"auth/types"
	"github.com/labstack/echo/v4"
)

func GetUserFromContext(c *echo.Context) (*types.LoggedInUser, error) {
	user, ok := (*c).Get("user").(*types.LoggedInUser)
	if !ok {
		return nil, errors2.NoLoggedInUserFound()
	}
	return user, nil
}

func GetUserFromHeader(c *echo.Context) (*types.LoggedInUser, error) {
	userIDString := (*c).Request().Header.Get(consts.HeaderUserIdKey)
	userID, _ := strconv.Atoi(userIDString)
	if userID == 0 {
		return nil, errors2.NoLoggedInUserFound()
	}
	currentUser := &types.LoggedInUser{
		ID: userID,
	}
	return currentUser, nil
}
