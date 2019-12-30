// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/mainflux/mainflux/twins/mqtt"

	kitprometheus "github.com/go-kit/kit/metrics/prometheus"
	"github.com/mainflux/mainflux"
	authapi "github.com/mainflux/mainflux/authn/api/grpc"
	"github.com/mainflux/mainflux/logger"
	localusers "github.com/mainflux/mainflux/things/users"
	"github.com/mainflux/mainflux/twins"
	"github.com/mainflux/mainflux/twins/api"
	twapi "github.com/mainflux/mainflux/twins/api/http"
	twmongodb "github.com/mainflux/mainflux/twins/mongodb"
	twnats "github.com/mainflux/mainflux/twins/nats"
	"github.com/mainflux/mainflux/twins/uuid"
	nats "github.com/nats-io/go-nats"
	opentracing "github.com/opentracing/opentracing-go"
	stdprometheus "github.com/prometheus/client_golang/prometheus"
	jconfig "github.com/uber/jaeger-client-go/config"
	"go.mongodb.org/mongo-driver/mongo"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	defLogLevel        = "info"
	defHTTPPort        = "9021"
	defJaegerURL       = ""
	defServerCert      = ""
	defServerKey       = ""
	defDBName          = "mainflux"
	defDBHost          = "localhost"
	defDBPort          = "27017"
	defSingleUserEmail = ""
	defSingleUserToken = ""
	defClientTLS       = "false"
	defCACerts         = ""
	defMqttURL         = "tcp://localhost:1883"
	defThingID         = ""
	defThingKey        = ""
	defChannelID       = ""
	defNatsURL         = nats.DefaultURL

	defAuthnGRPCPort = "8181"
	defAuthnTimeout  = "1" // in seconds
	defAuthnURL      = "localhost"

	envLogLevel        = "MF_TWINS_LOG_LEVEL"
	envHTTPPort        = "MF_TWINS_HTTP_PORT"
	envJaegerURL       = "MF_JAEGER_URL"
	envServerCert      = "MF_TWINS_SERVER_CERT"
	envServerKey       = "MF_TWINS_SERVER_KEY"
	envDBName          = "MF_TWINS_DB_NAME"
	envDBHost          = "MF_TWINS_DB_HOST"
	envDBPort          = "MF_TWINS_DB_PORT"
	envSingleUserEmail = "MF_TWINS_SINGLE_USER_EMAIL"
	envSingleUserToken = "MF_TWINS_SINGLE_USER_TOKEN"
	envClientTLS       = "MF_TWINS_CLIENT_TLS"
	envCACerts         = "MF_TWINS_CA_CERTS"
	envMqttURL         = "MF_TWINS_MQTT_URL"
	envThingID         = "MF_TWINS_THING_ID"
	envThingKey        = "MF_TWINS_THING_KEY"
	envChannelID       = "MF_TWINS_CHANNEL_ID"
	envNatsURL         = "MF_NATS_URL"

	envAuthnGRPCPort = "MF_AUTHN_GRPC_PORT"
	envAuthnTimeout  = "MF_AUTHN_TIMEOUT"
	envAuthnURL      = "MF_AUTHN_URL"
)

type config struct {
	logLevel        string
	httpPort        string
	jaegerURL       string
	serverCert      string
	serverKey       string
	dbCfg           twmongodb.Config
	singleUserEmail string
	singleUserToken string
	clientTLS       bool
	caCerts         string
	mqttURL         string
	thingID         string
	thingKey        string
	channelID       string
	NatsURL         string

	authnGRPCPort string
	authnTimeout  time.Duration
	authnURL      string
}

func main() {
	cfg := loadConfig()

	logger, err := logger.New(os.Stdout, cfg.logLevel)
	if err != nil {
		log.Fatalf(err.Error())
	}

	db, err := twmongodb.Connect(cfg.dbCfg, logger)
	if err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}

	authTracer, authCloser := initJaeger("auth", cfg.jaegerURL, logger)
	defer authCloser.Close()

	auth, close := createAuthClient(cfg, authTracer, logger)
	if close != nil {
		defer close()
	}

	dbTracer, dbCloser := initJaeger("twins_db", cfg.jaegerURL, logger)
	defer dbCloser.Close()

	pc := mqtt.Connect(cfg.mqttURL, cfg.thingID, cfg.thingKey, logger)
	mc := mqtt.New(pc, cfg.channelID)

	mcTracer, mcCloser := initJaeger("twins_mqtt", cfg.jaegerURL, logger)
	defer mcCloser.Close()

	nc, err := nats.Connect(cfg.NatsURL)
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to connect to NATS: %s", err))
		os.Exit(1)
	}
	defer nc.Close()

	ncTracer, ncCloser := initJaeger("twins_nats", cfg.jaegerURL, logger)
	defer ncCloser.Close()

	tracer, closer := initJaeger("twins", cfg.jaegerURL, logger)
	defer closer.Close()

	svc := newService(nc, ncTracer, mc, mcTracer, auth, dbTracer, db, logger)
	errs := make(chan error, 2)

	go startHTTPServer(twapi.MakeHandler(tracer, svc), cfg.httpPort, cfg, logger, errs)

	go func() {
		c := make(chan os.Signal)
		signal.Notify(c, syscall.SIGINT)
		errs <- fmt.Errorf("%s", <-c)
	}()

	err = <-errs
	logger.Error(fmt.Sprintf("Twins service terminated: %s", err))
}

func loadConfig() config {
	tls, err := strconv.ParseBool(mainflux.Env(envClientTLS, defClientTLS))
	if err != nil {
		log.Fatalf("Invalid value passed for %s\n", envClientTLS)
	}

	timeout, err := strconv.ParseInt(mainflux.Env(envAuthnTimeout, defAuthnTimeout), 10, 64)
	if err != nil {
		log.Fatalf("Invalid %s value: %s", envAuthnTimeout, err.Error())
	}

	dbCfg := twmongodb.Config{
		Name: mainflux.Env(envDBName, defDBName),
		Host: mainflux.Env(envDBHost, defDBHost),
		Port: mainflux.Env(envDBPort, defDBPort),
	}

	return config{
		logLevel:        mainflux.Env(envLogLevel, defLogLevel),
		httpPort:        mainflux.Env(envHTTPPort, defHTTPPort),
		serverCert:      mainflux.Env(envServerCert, defServerCert),
		serverKey:       mainflux.Env(envServerKey, defServerKey),
		jaegerURL:       mainflux.Env(envJaegerURL, defJaegerURL),
		dbCfg:           dbCfg,
		singleUserEmail: mainflux.Env(envSingleUserEmail, defSingleUserEmail),
		singleUserToken: mainflux.Env(envSingleUserToken, defSingleUserToken),
		clientTLS:       tls,
		caCerts:         mainflux.Env(envCACerts, defCACerts),
		mqttURL:         mainflux.Env(envMqttURL, defMqttURL),
		thingID:         mainflux.Env(envThingID, defThingID),
		channelID:       mainflux.Env(envChannelID, defChannelID),
		thingKey:        mainflux.Env(envThingKey, defThingKey),
		NatsURL:         mainflux.Env(envNatsURL, defNatsURL),
		authnGRPCPort:   mainflux.Env(envAuthnGRPCPort, defAuthnGRPCPort),
		authnURL:        mainflux.Env(envAuthnURL, defAuthnURL),
		authnTimeout:    time.Duration(timeout) * time.Second,
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

func createAuthClient(cfg config, tracer opentracing.Tracer, logger logger.Logger) (mainflux.AuthNServiceClient, func() error) {
	if cfg.singleUserEmail != "" && cfg.singleUserToken != "" {
		return localusers.NewSingleUserService(cfg.singleUserEmail, cfg.singleUserToken), nil
	}

	conn := connectToAuth(cfg, logger)
	return authapi.NewClient(tracer, conn, cfg.authnTimeout), conn.Close
}

func connectToAuth(cfg config, logger logger.Logger) *grpc.ClientConn {
	var opts []grpc.DialOption
	if cfg.clientTLS {
		if cfg.caCerts != "" {
			tpc, err := credentials.NewClientTLSFromFile(cfg.caCerts, "")
			if err != nil {
				logger.Error(fmt.Sprintf("Failed to create tls credentials: %s", err))
				os.Exit(1)
			}
			opts = append(opts, grpc.WithTransportCredentials(tpc))
		}
	} else {
		opts = append(opts, grpc.WithInsecure())
		logger.Info("gRPC communication is not encrypted")
	}

	authnURL := fmt.Sprintf("%s:%s", cfg.authnURL, cfg.authnGRPCPort)
	conn, err := grpc.Dial(authnURL, opts...)
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to connect to auth service: %s", err))
		os.Exit(1)
	}

	return conn
}

func newService(nc *nats.Conn, ncTracer opentracing.Tracer, mc mqtt.Mqtt, mcTracer opentracing.Tracer, users mainflux.AuthNServiceClient, dbTracer opentracing.Tracer, db *mongo.Database, logger logger.Logger) twins.Service {
	twinRepo := twmongodb.NewTwinRepository(db)
	stateRepo := twmongodb.NewStateRepository(db)
	idp := uuid.New()

	svc := twins.New(nc, mc, users, twinRepo, stateRepo, idp)
	svc = api.LoggingMiddleware(svc, logger)
	svc = api.MetricsMiddleware(
		svc,
		kitprometheus.NewCounterFrom(stdprometheus.CounterOpts{
			Namespace: "twins",
			Subsystem: "api",
			Name:      "request_count",
			Help:      "Number of requests received.",
		}, []string{"method"}),
		kitprometheus.NewSummaryFrom(stdprometheus.SummaryOpts{
			Namespace: "twins",
			Subsystem: "api",
			Name:      "request_latency_microseconds",
			Help:      "Total duration of requests in microseconds.",
		}, []string{"method"}),
	)

	twnats.Subscribe(nc, mc, svc, logger)

	return svc
}

func startHTTPServer(handler http.Handler, port string, cfg config, logger logger.Logger, errs chan error) {
	p := fmt.Sprintf(":%s", port)
	if cfg.serverCert != "" || cfg.serverKey != "" {
		logger.Info(fmt.Sprintf("Twins service started using https on port %s with cert %s key %s",
			port, cfg.serverCert, cfg.serverKey))
		errs <- http.ListenAndServeTLS(p, cfg.serverCert, cfg.serverKey, handler)
		return
	}
	logger.Info(fmt.Sprintf("Twins service started using http on port %s", cfg.httpPort))
	errs <- http.ListenAndServe(p, handler)
}
