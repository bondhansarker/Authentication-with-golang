package router

import (
	"auth/config"
	c "auth/controllers"
	m "auth/middlewares"

	"github.com/labstack/echo/v4"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var e = echo.New()

func Init() {
	m.Init(e)
	e.GET("/metrics", echo.WrapHandler(promhttp.Handler()))

	registerRoutes(e)

	port := config.App().Port
	e.Logger.Fatal(e.Start(":" + port))
}

func registerRoutes(e *echo.Echo) {
	g := e.Group("/v1")

	// Unauthenticated routes
	g.POST("/signup", c.Signup)
	g.POST("/login", c.Login)
	g.POST("/login/social", c.SocialLogin)
	g.POST("/token/refresh", c.RefreshToken)
	g.GET("/token/verify", c.VerifyToken)
	g.POST("/password/forgot", c.ForgotPassword)
	g.POST("/password/forgot/otp/resend", c.ResendForgotPasswordOtp)
	g.POST("/password/verify-reset", c.VerifyResetPassword)
	g.POST("/password/reset", c.ResetPassword)

	// Authenticated Routes
	g.POST("/logout", c.Logout, m.Auth())
	g.POST("/password/change", c.ChangePassword, m.Auth())
	g.GET("/profile", c.GetUser, m.Auth())
	g.PATCH("/profile", c.UpdateUser, m.Auth())

}
