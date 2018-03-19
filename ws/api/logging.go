package api

import (
	"time"

	"github.com/go-kit/kit/log"
	"github.com/gorilla/websocket"
	"github.com/mainflux/mainflux"
	"github.com/mainflux/mainflux/ws"
)

var _ ws.Service = (*loggingMiddleware)(nil)

type loggingMiddleware struct {
	logger log.Logger
	svc    ws.Service
}

// LoggingMiddleware adds logging facilities to the adapter.
func LoggingMiddleware(svc ws.Service, logger log.Logger) ws.Service {
	return &loggingMiddleware{logger, svc}
}

func (lm *loggingMiddleware) Publish(msg mainflux.RawMessage) error {
	defer func(begin time.Time) {
		lm.logger.Log(
			"method", "publish",
			"took", time.Since(begin),
		)
	}(time.Now())

	return lm.svc.Publish(msg)
}

func (lm *loggingMiddleware) BroadcastMessage(msg mainflux.RawMessage) {
	defer func(begin time.Time) {
		lm.logger.Log(
			"method", "broadcast_message",
			"took", time.Since(begin),
		)
	}(time.Now())

	lm.svc.BroadcastMessage(msg)
}

func (lm *loggingMiddleware) AddConnection(pair ws.IDPair, conn *websocket.Conn) {
	defer func(begin time.Time) {
		lm.logger.Log(
			"method", "add_connection",
			"took", time.Since(begin),
		)
	}(time.Now())

	lm.svc.AddConnection(pair, conn)
}
