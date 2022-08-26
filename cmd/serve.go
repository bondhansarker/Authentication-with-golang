package cmd

import (
	repoImpl "auth/repositories/impl"
	serviceImpl "auth/services/impl"

	"auth/config"
	"auth/connection"
	"auth/controllers"
	"auth/middlewares"
	"auth/routes"
	"auth/server"
	"github.com/labstack/echo/v4"
	"github.com/spf13/cobra"
)

var serveCmd = &cobra.Command{
	Use: "serve",
	Run: serve,
}

func serve(cmd *cobra.Command, args []string) {
	// config
	config.Load()
	cfg := config.AllConfig()

	// connection
	connection.Redis(cfg.Redis)
	connection.Db(cfg.Db)

	// mysql
	var dbClient = connection.DbClient()

	// redis
	var cacheClient = connection.RedisClient()

	// repositories
	var userRepo = repoImpl.NewUserRepository(dbClient)
	var cacheRepo = repoImpl.NewRedisRepository(cacheClient)
	var tokenRepo = repoImpl.NewJWTRepository(cfg, cacheRepo)

	// services
	var userSvc = serviceImpl.NewUserService(cfg, cacheRepo, userRepo)
	var oAuthLoginSvc = serviceImpl.NewOAuthService(cfg, userSvc)
	var authSvc = serviceImpl.NewAuthService(cfg, cacheRepo, tokenRepo, userSvc, oAuthLoginSvc)

	// middlewares
	var middleware = middlewares.NewJWTMiddleWare(cfg.Redis, cacheRepo)

	// controllers
	var authCtr = controllers.NewAuthController(authSvc)
	var userCtr = controllers.NewUserController(userSvc)
	var adminCtr = controllers.NewAdminController(userSvc)

	// Server
	var framework = echo.New()
	var Routes = routes.New(framework, middleware, authCtr, userCtr, adminCtr)
	var Server = server.New(cfg, framework)

	Routes.Init()
	Server.Start()
}
