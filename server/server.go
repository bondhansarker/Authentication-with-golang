package server

import (
	"context"
	"os"
	"os/signal"
	"time"

	"auth/config"
	"auth/utils/log"
	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"
)

type Server struct {
	framework *echo.Echo
	config    *config.Config
}

func New(config *config.Config, framework *echo.Echo) *Server {
	return &Server{
		config:    config,
		framework: framework,
	}
}

func (s *Server) Start() {
	e := s.framework
	s.setLoggerConfig()
	// start routes server
	go func() {
		e.Logger.Fatal(e.Start(":" + s.config.App.Port))
	}()
	// graceful shutdown
	s.GracefulShutdown()
}

func (s *Server) setLoggerConfig() {
	// logger
	log.SetLogFormatter(&logrus.TextFormatter{})
	log.SetLogOutput(os.Stdout)
	log.SetLogLevel(logrus.InfoLevel)
}

// GracefulShutdown server will gracefully shut down within 5 sec
func (s *Server) GracefulShutdown() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	<-ch
	log.Info("shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_ = s.framework.Shutdown(ctx)
	log.Info("server shutdowns gracefully")
}
