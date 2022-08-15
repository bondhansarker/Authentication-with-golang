package routes

import (
	"auth/controllers"
	"auth/middlewares"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/labstack/echo/v4"
)

type Routes struct {
	echo            *echo.Echo
	middleware      *middlewares.JWTMiddleware
	authController  *controllers.AuthController
	userController  *controllers.UserController
	adminController *controllers.AdminController
}

func New(echo *echo.Echo,
	middleware *middlewares.JWTMiddleware,
	authController *controllers.AuthController,
	userController *controllers.UserController,
	adminController *controllers.AdminController) *Routes {
	return &Routes{
		echo:            echo,
		middleware:      middleware,
		authController:  authController,
		userController:  userController,
		adminController: adminController,
	}
}

func (r *Routes) Init() {
	e := r.echo
	middlewares.Init(e)
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
	v1.POST("/logout", r.authController.Logout, middlewares.Auth(r.middleware))
	v1.POST("/password/change", r.userController.ChangePassword, middlewares.Auth(r.middleware))

	// Authenticated Routes from header
	v1.GET("/profile", r.userController.GetUser)
	v1.PATCH("/profile", r.userController.UpdateUser)
	v1.PATCH("/profile-pic", r.userController.UpdateProfilePic)
	v1.PATCH("/user-statistics", r.userController.UpdateUserStat)

	// Admin Routes
	v1.GET("/users", r.adminController.FindUsers, middlewares.Auth(r.middleware))
	v1.GET("/users/:id", r.adminController.FindUser, middlewares.Auth(r.middleware))
	v1.PATCH("/users/:id", r.adminController.UpdateUser, middlewares.Auth(r.middleware))
	v1.DELETE("/users/:id", r.adminController.DeleteUser, middlewares.Auth(r.middleware))
}
