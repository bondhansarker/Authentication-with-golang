package server

import (
	"context"
	"os"
	"os/signal"
	"time"

	"auth/config"
	"auth/utils/log"
	"github.com/labstack/echo/v4"
)

type Server struct {
	echo   *echo.Echo
	config *config.Config
}

func New(echo *echo.Echo) *Server {
	return &Server{
		echo:   echo,
		config: config.AllConfig(),
	}
}

func (s *Server) Start() {
	e := s.echo
	// start routes server
	go func() {
		e.Logger.Fatal(e.Start(":" + s.config.App.Port))
	}()
	// graceful shutdown
	s.GracefulShutdown()
}

// GracefulShutdown server will gracefully shut down within 5 sec
func (s *Server) GracefulShutdown() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	<-ch
	log.Info("shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_ = s.echo.Shutdown(ctx)
	log.Info("server shutdowns gracefully")
}
