package server

import (
	"auth/config"
	"github.com/labstack/echo/v4"
)

type Server struct {
	echo   *echo.Echo
	config *config.Config
}

func New(echo *echo.Echo) *Server {
	return &Server{
		echo:   echo,
		config: config.GetConfig(),
	}
}

func (s *Server) Start() {
	e := s.echo
	e.Logger.Fatal(e.Start(":" + s.config.App.Port))
}
