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

	registerRoutes(e.Group("api"))

	port := config.App().Port
	e.Logger.Fatal(e.Start(":" + port))
}

func registerRoutes(g interface{}) {
	const VersionPrefix = "/v1"
	grp := g.(*echo.Group)
	grp = grp.Group(VersionPrefix)

	// Unauthenticated routes
	grp.POST("/signup", c.Signup)
	grp.POST("/login", c.Login)
	grp.POST("/login/social", c.SocialLogin)
	grp.POST("/token/refresh", c.RefreshToken)
	grp.GET("/token/verify", c.VerifyToken)
	grp.POST("/password/forgot", c.ForgotPassword)
	grp.POST("/password/forgot/otp/resend", c.ResendForgotPasswordOtp)
	grp.POST("/password/verify-reset", c.VerifyResetPassword)
	grp.POST("/password/reset", c.ResetPassword)

	// Authenticated Routes
	grp.POST("/logout", c.Logout, m.Auth())
	grp.POST("/password/change", c.ChangePassword, m.Auth())
	grp.GET("/profile", c.GetUser, m.Auth())
	grp.PATCH("/profile", c.UpdateUser, m.Auth())

}
