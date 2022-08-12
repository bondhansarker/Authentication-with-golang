package middlewares

import (
	"auth/config"
	"github.com/labstack/echo/v4"
)

func Auth(middleware *JWTMiddleware) echo.MiddlewareFunc {
	return middleware.JWTWithConfig(JWTConfig{
		SigningKey: []byte(config.Jwt().AccessTokenSecret),
		ContextKey: config.Jwt().ContextKey,
	})
}
