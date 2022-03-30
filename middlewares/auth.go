package middlewares

import (
	"auth/config"

	"github.com/labstack/echo/v4"
)

func Auth() echo.MiddlewareFunc {
	return JWTWithConfig(JWTConfig{
		SigningKey: []byte(config.Jwt().AccessTokenSecret),
		ContextKey: config.Jwt().ContextKey,
	})
}
