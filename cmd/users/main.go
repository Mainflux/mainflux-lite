package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	kitprometheus "github.com/go-kit/kit/metrics/prometheus"
	"github.com/mainflux/mainflux"
	log "github.com/mainflux/mainflux/logger"
	"github.com/mainflux/mainflux/users"
	"github.com/mainflux/mainflux/users/api"
	grpcapi "github.com/mainflux/mainflux/users/api/grpc"
	httpapi "github.com/mainflux/mainflux/users/api/http"
	"github.com/mainflux/mainflux/users/bcrypt"
	"github.com/mainflux/mainflux/users/jwt"
	"github.com/mainflux/mainflux/users/postgres"
	stdprometheus "github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
)

const (
	defDBHost   = "localhost"
	defDBPort   = "5432"
	defDBUser   = "mainflux"
	defDBPass   = "mainflux"
	defDBName   = "users"
	defHTTPPort = "8180"
	defGRPCPort = "8181"
	defSecret   = "users"
	envDBHost   = "MF_USERS_DB_HOST"
	envDBPort   = "MF_USERS_DB_PORT"
	envDBUser   = "MF_USERS_DB_USER"
	envDBPass   = "MF_USERS_DB_PASS"
	envDBName   = "MF_USERS_DB"
	envHTTPPort = "MF_USERS_HTTP_PORT"
	envGRPCPort = "MF_USERS_GRPC_PORT"
	envSecret   = "MF_USERS_SECRET"
)

type config struct {
	DBHost   string
	DBPort   string
	DBUser   string
	DBPass   string
	DBName   string
	HTTPPort string
	GRPCPort string
	Secret   string
}

func main() {
	cfg := config{
		DBHost:   mainflux.Env(envDBHost, defDBHost),
		DBPort:   mainflux.Env(envDBPort, defDBPort),
		DBUser:   mainflux.Env(envDBUser, defDBUser),
		DBPass:   mainflux.Env(envDBPass, defDBPass),
		DBName:   mainflux.Env(envDBName, defDBName),
		HTTPPort: mainflux.Env(envHTTPPort, defHTTPPort),
		GRPCPort: mainflux.Env(envGRPCPort, defGRPCPort),
		Secret:   mainflux.Env(envSecret, defSecret),
	}

	logger := log.New(os.Stdout)

	db, err := postgres.Connect(cfg.DBHost, cfg.DBPort, cfg.DBName, cfg.DBUser, cfg.DBPass)
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to connect to postgres: %s", err))
		os.Exit(1)
	}
	defer db.Close()

	repo := postgres.New(db)
	hasher := bcrypt.New()
	idp := jwt.New(cfg.Secret)

	svc := users.New(repo, hasher, idp)
	svc = api.LoggingMiddleware(svc, logger)
	svc = api.MetricsMiddleware(
		svc,
		kitprometheus.NewCounterFrom(stdprometheus.CounterOpts{
			Namespace: "users",
			Subsystem: "api",
			Name:      "request_count",
			Help:      "Number of requests received.",
		}, []string{"method"}),
		kitprometheus.NewSummaryFrom(stdprometheus.SummaryOpts{
			Namespace: "users",
			Subsystem: "api",
			Name:      "request_latency_microseconds",
			Help:      "Total duration of requests in microseconds.",
		}, []string{"method"}),
	)

	errs := make(chan error, 2)

	go startHTTPServer(svc, cfg.HTTPPort, logger, errs)

	go startGRPCServer(svc, cfg.GRPCPort, logger, errs)

	go func() {
		c := make(chan os.Signal)
		signal.Notify(c, syscall.SIGINT)
		errs <- fmt.Errorf("%s", <-c)
	}()

	err = <-errs
	logger.Error(fmt.Sprintf("Users service terminated: %s", err))
}

func startHTTPServer(svc users.Service, port string, logger log.Logger, errs chan error) {
	p := fmt.Sprintf(":%s", port)
	logger.Info(fmt.Sprintf("Users HTTP service started, exposed port %s", port))
	errs <- http.ListenAndServe(p, httpapi.MakeHandler(svc, logger))
}

func startGRPCServer(svc users.Service, port string, logger log.Logger, errs chan error) {
	p := fmt.Sprintf(":%s", port)
	listener, err := net.Listen("tcp", p)
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to listen on port %s: %s", port, err))
	}
	baseServer := grpc.NewServer()
	grpcapi.RegisterUsersServiceServer(baseServer, grpcapi.NewServer(svc))
	logger.Info(fmt.Sprintf("Users gRPC service started, exposed port %s", port))
	errs <- baseServer.Serve(listener)
}
