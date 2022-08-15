package cmd

import (
	"auth/models"
	repoImpl "auth/repositories/impl"
	serviceImpl "auth/services/impl"
	"os"

	"auth/config"
	"auth/connection"
	"auth/controllers"
	"auth/middlewares"
	"auth/routes"
	"auth/server"
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

	//generics
	models.InitGenericModel(dbClient)
	repoImpl.InitGenericRepository(dbClient)

	// repositories
	var userRepo = repoImpl.NewUserRepository(dbClient)

	// services
	var cacheSvc = serviceImpl.NewRedisService(redisClient)
	var tokenSvc = serviceImpl.NewJWTService(cacheSvc)
	var userSvc = serviceImpl.NewUserService(cacheSvc, userRepo)
	var oAuthLoginSvc = serviceImpl.NewOAuthService(userSvc)
	var authSvc = serviceImpl.NewAuthService(cacheSvc, tokenSvc, userSvc, oAuthLoginSvc)

	// middlewares
	var middleware = middlewares.NewJWTMiddleWare(cacheSvc)

	// controllers
	var authCtr = controllers.NewAuthController(authSvc)
	var userCtr = controllers.NewUserController(userSvc)
	var adminCtr = controllers.NewAdminController(userSvc)

	// Server
	var echo_ = echo.New()
	var Routes = routes.New(echo_, middleware, authCtr, userCtr, adminCtr)
	var Server = server.New(echo_)

	Routes.Init()
	Server.Start()
}
