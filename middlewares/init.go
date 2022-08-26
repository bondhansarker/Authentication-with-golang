package middlewares

import (
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func Init(e *echo.Echo) {
	e.Pre(middleware.RemoveTrailingSlash())
	e.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{
		Format: "status=${status}, method=${method}, uri=${uri}, rest_errors='${rest_errors}'\n",
	}))
	e.Use(middleware.CORS())
	e.Use(middleware.Secure())
	e.Use(middleware.Recover())
	e.Use(middleware.GzipWithConfig(middleware.GzipConfig{
		Skipper: func(context echo.Context) bool {
			return context.Request().URL.Path == "/metrics"
		},
		Level: 5,
	}))
}
