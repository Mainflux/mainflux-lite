//
// Copyright (c) 2019
// Mainflux
//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/mainflux/mainflux"
	"github.com/mainflux/mainflux/logger"
	"github.com/mainflux/mainflux/twin"
	"github.com/mainflux/mainflux/twin/api"
	twinhttpapi "github.com/mainflux/mainflux/twin/api/twin/http"
	twinmongodb "github.com/mainflux/mainflux/twin/mongodb"
	"go.mongodb.org/mongo-driver/mongo"

	kitprometheus "github.com/go-kit/kit/metrics/prometheus"
	opentracing "github.com/opentracing/opentracing-go"
	stdprometheus "github.com/prometheus/client_golang/prometheus"
	jconfig "github.com/uber/jaeger-client-go/config"
)

const (
	defLogLevel   = "info"
	defHTTPPort   = "9021"
	defJaegerURL  = ""
	defServerCert = ""
	defServerKey  = ""
	defSecret     = "secret"
	defDBName     = "mainflux"
	defDBHost     = "localhost"
	defDBPort     = "29021"

	envLogLevel   = "MF_TWIN_LOG_LEVEL"
	envHTTPPort   = "MF_TWIN_HTTP_PORT"
	envJaegerURL  = "MF_JAEGER_URL"
	envServerCert = "MF_TWIN_SERVER_CERT"
	envServerKey  = "MF_TWIN_SERVER_KEY"
	envSecret     = "MF_TWIN_SECRET"
	envDBName     = "MF_MONGODB_NAME"
	envDBHost     = "MF_MONGODB_HOST"
	envDBPort     = "MF_MONGODB_PORT"
)

type config struct {
	logLevel     string
	httpPort     string
	authHTTPPort string
	authGRPCPort string
	jaegerURL    string
	serverCert   string
	serverKey    string
	secret       string
	dbCfg        twinmongodb.Config
}

func main() {
	cfg := loadConfig()

	logger, err := logger.New(os.Stdout, cfg.logLevel)
	if err != nil {
		log.Fatalf(err.Error())
	}

	db, err := twinmongodb.Connect(cfg.dbCfg, logger)
	if err != nil {
		log.Fatalf(err.Error())
	}

	// dbTracer, dbCloser := initJaeger("twin_db", cfg.jaegerURL, logger)
	// defer dbCloser.Close()

	tracer, closer := initJaeger("twin", cfg.jaegerURL, logger)
	defer closer.Close()

	svc := newService(cfg.secret, db, logger)
	errs := make(chan error, 2)

	go startHTTPServer(twinhttpapi.MakeHandler(tracer, svc), cfg.httpPort, cfg, logger, errs)

	go func() {
		c := make(chan os.Signal)
		signal.Notify(c, syscall.SIGINT)
		errs <- fmt.Errorf("%s", <-c)
	}()

	err = <-errs
	logger.Error(fmt.Sprintf("Twin service terminated: %s", err))
}

func loadConfig() config {

	dbCfg := twinmongodb.Config{
		Name: mainflux.Env(envDBName, defDBName),
		Host: mainflux.Env(envDBHost, defDBHost),
		Port: mainflux.Env(envDBPort, defDBPort),
	}

	return config{
		logLevel:   mainflux.Env(envLogLevel, defLogLevel),
		httpPort:   mainflux.Env(envHTTPPort, defHTTPPort),
		serverCert: mainflux.Env(envServerCert, defServerCert),
		serverKey:  mainflux.Env(envServerKey, defServerKey),
		jaegerURL:  mainflux.Env(envJaegerURL, defJaegerURL),
		secret:     mainflux.Env(envSecret, defSecret),
		dbCfg:      dbCfg,
	}
}

func initJaeger(svcName, url string, logger logger.Logger) (opentracing.Tracer, io.Closer) {
	if url == "" {
		return opentracing.NoopTracer{}, ioutil.NopCloser(nil)
	}

	tracer, closer, err := jconfig.Configuration{
		ServiceName: svcName,
		Sampler: &jconfig.SamplerConfig{
			Type:  "const",
			Param: 1,
		},
		Reporter: &jconfig.ReporterConfig{
			LocalAgentHostPort: url,
			LogSpans:           true,
		},
	}.NewTracer()
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to init Jaeger client: %s", err))
		os.Exit(1)
	}

	return tracer, closer
}

func newService(secret string, db *mongo.Database, logger logger.Logger) twin.Service {
	svc := twin.New(secret, db)

	svc = api.LoggingMiddleware(svc, logger)
	svc = api.MetricsMiddleware(
		svc,
		kitprometheus.NewCounterFrom(stdprometheus.CounterOpts{
			Namespace: "twin",
			Subsystem: "api",
			Name:      "request_count",
			Help:      "Number of requests received.",
		}, []string{"method"}),
		kitprometheus.NewSummaryFrom(stdprometheus.SummaryOpts{
			Namespace: "twin",
			Subsystem: "api",
			Name:      "request_latency_microseconds",
			Help:      "Total duration of requests in microseconds.",
		}, []string{"method"}),
	)

	return svc
}

func startHTTPServer(handler http.Handler, port string, cfg config, logger logger.Logger, errs chan error) {
	p := fmt.Sprintf(":%s", port)
	if cfg.serverCert != "" || cfg.serverKey != "" {
		logger.Info(fmt.Sprintf("Twin service started using https on port %s with cert %s key %s",
			port, cfg.serverCert, cfg.serverKey))
		errs <- http.ListenAndServeTLS(p, cfg.serverCert, cfg.serverKey, handler)
		return
	}
	logger.Info(fmt.Sprintf("Twin service started using http on port %s", cfg.httpPort))
	errs <- http.ListenAndServe(p, handler)
}