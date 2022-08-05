package middlewares

import (
	"github.com/labstack/echo/v4"
)

func Auth(jwtMiddleware *JWTMiddleWare) echo.MiddlewareFunc {
	return jwtMiddleware.JWTWithConfig(JWTConfig{
		SigningKey: []byte(jwtMiddleware.config.Jwt.AccessTokenSecret),
		ContextKey: jwtMiddleware.config.Jwt.ContextKey,
	})
}
