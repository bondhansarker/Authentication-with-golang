package cmd

import (
	"os"

	"auth/config"
	"auth/connection"
	"auth/controllers"
	"auth/middlewares"
	"auth/repositories"
	"auth/routes"
	"auth/server"
	"auth/services"
	"auth/utils/log"
	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var serveCmd = &cobra.Command{
	Use: "serve",
	Run: serve,
}

func serve(cmd *cobra.Command, args []string) {
	// logger
	// Log as JSON instead of the default ASCII formatter.
	log.SetLogFormatter(&logrus.TextFormatter{})
	log.SetLogOutput(os.Stdout)
	log.SetLogLevel(logrus.InfoLevel)

	// config
	config.Load()

	// connection
	connection.Redis()
	connection.Db()

	// mysql
	var dbClient = connection.DbClient()

	// redis
	var redisClient = connection.RedisClient()

	// repositories
	var redisRepository = repositories.NewRedisRepository(redisClient)
	var userRepository = repositories.NewUserRepository(dbClient)

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
