package routes

import (
	"auth/controllers"
	m "auth/middlewares"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/labstack/echo/v4"
)

type Routes struct {
	echo            *echo.Echo
	jwtMiddleware   *m.JWTMiddleWare
	authController  *controllers.AuthController
	userController  *controllers.UserController
	adminController *controllers.AdminController
}

func New(echo *echo.Echo,
	jwtMiddleware *m.JWTMiddleWare,
	authController *controllers.AuthController,
	userController *controllers.UserController,
	adminController *controllers.AdminController) *Routes {
	return &Routes{
		echo:            echo,
		jwtMiddleware:   jwtMiddleware,
		authController:  authController,
		userController:  userController,
		adminController: adminController,
	}
}

func (r *Routes) Init() {
	e := r.echo
	m.Init(e)
	e.GET("/metrics", echo.WrapHandler(promhttp.Handler()))

	r.registerRoutes(e)
}

func (r *Routes) registerRoutes(e *echo.Echo) {
	v1 := e.Group("/v1")

	// Unauthenticated routes
	v1.POST("/signup", r.authController.Signup)
	v1.POST("/login", r.authController.Login)
	v1.POST("/login/social", r.authController.SocialLogin)
	v1.POST("/token/refresh", r.authController.RefreshToken)
	v1.GET("/token/verify", r.authController.VerifyToken)
	v1.POST("/password/forgot", r.userController.ForgotPassword)
	v1.POST("/password/forgot/otp/resend", r.userController.ResendForgotPasswordOtp)
	v1.POST("/password/verify-reset", r.userController.VerifyResetPassword)
	v1.POST("/password/reset", r.userController.ResetPassword)

	// Authenticated Routes from context
	v1.POST("/logout", r.authController.Logout, m.Auth(r.jwtMiddleware))
	v1.POST("/password/change", r.userController.ChangePassword, m.Auth(r.jwtMiddleware))

	// Authenticated Routes from header
	v1.GET("/profile", r.userController.GetUser)
	v1.PATCH("/profile", r.userController.UpdateUser)
	v1.PATCH("/profile-pic", r.userController.UpdateProfilePic)
	v1.PATCH("/user-statistics", r.userController.UpdateUserStat)

	// Admin Routes
	v1.GET("/users", r.adminController.FindUsers, m.Auth(r.jwtMiddleware))
	v1.GET("/users/:id", r.adminController.FindUser, m.Auth(r.jwtMiddleware))
	v1.PATCH("/users/:id", r.adminController.UpdateUser, m.Auth(r.jwtMiddleware))
}
