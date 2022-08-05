package cmd

import (
	"os"

	"auth/config"
	"auth/connections"
	"auth/controllers"
	"auth/middlewares"
	"auth/repositories"
	"auth/routes"
	"auth/server"
	"auth/services"
	"github.com/labstack/echo/v4"
	log "github.com/sirupsen/logrus"

	"github.com/spf13/cobra"
)

var serveCmd = &cobra.Command{
	Use: "serve",
	Run: serve,
}

func serve(cmd *cobra.Command, args []string) {
	// Logger
	log.SetOutput(os.Stdout)
	log.SetLevel(log.InfoLevel)

	// Config
	config.Load()

	// Mysql
	var dbClient = connections.NewDbClient()

	// Redis
	var redisClient = connections.NewRedisClient()

	// Repositories
	var redisRepository = repositories.NewRedisRepository(redisClient)
	var userRepository = repositories.NewUserRepository(dbClient, redisRepository)

	// middlewares
	var jwtMiddleware = middlewares.NewJWTMiddleWare(redisRepository)

	// services
	var jwtService = services.NewJWTService(redisRepository)
	var userService = services.NewUserService(redisRepository, userRepository)
	var authService = services.NewAuthService(redisRepository, jwtService, userService)

	// controllers
	var authController = controllers.NewAuthController(userService, authService)
	var userController = controllers.NewUserController(userService)
	var adminController = controllers.NewAdminController(userService)

	// Server
	var echo_ = echo.New()
	var Routes = routes.New(echo_, jwtMiddleware, authController, userController, adminController)
	var Server = server.New(echo_)

	Routes.Init()
	Server.Start()
}
