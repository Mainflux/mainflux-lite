// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

// Package coap contains the domain concept definitions needed to support
// Mainflux coap adapter service functionality. All constant values are taken
// from RFC, and could be adjusted based on specific use case.
package coap

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/mainflux/mainflux"
	broker "github.com/mainflux/mainflux/brokers/nats"
	"github.com/nats-io/nats.go"
)

const (
	chanID    = "id"
	keyHeader = "key"

	// AckRandomFactor is default ACK coefficient.
	AckRandomFactor = 1.5
	// AckTimeout is the amount of time to wait for a response.
	AckTimeout = 2000 * time.Millisecond
	// MaxRetransmit is the maximum number of times a message will be retransmitted.
	MaxRetransmit = 4
)

var (
	errBadOption = errors.New("bad option")
	// ErrFailedMessagePublish indicates that message publishing failed.
	ErrFailedMessagePublish = errors.New("failed to publish message")

	// ErrFailedSubscription indicates that client couldn't subscribe to specified channel.
	ErrFailedSubscription = errors.New("failed to subscribe to a channel")

	// ErrFailedConnection indicates that service couldn't connect to message broker.
	ErrFailedConnection = errors.New("failed to connect to message broker")
)

// Service specifies coap service API.
type Service interface {
	// Publish Messssage
	Publish(context.Context, string, mainflux.Message) error

	// Subscribes to channel with specified id, subtopic and adds subscription to
	// service map of subscriptions under given ID.
	Subscribe(string, string, string, *Observer) error

	// Unsubscribe method is used to stop observing resource.
	Unsubscribe(string)
}

var _ Service = (*adapterService)(nil)

type adapterService struct {
	auth    mainflux.ThingsServiceClient
	pub     broker.NatsPublisher
	sub     broker.NatsSubscriber
	obs     map[string]*Observer
	obsLock sync.Mutex
}

const prefix = "channel"

// New instantiates the CoAP adapter implementation.
func New(pub broker.NatsPublisher, sub broker.NatsSubscriber, auth mainflux.ThingsServiceClient, responses <-chan string) Service {
	as := &adapterService{
		auth:    auth,
		pub:     pub,
		sub:     sub,
		obs:     make(map[string]*Observer),
		obsLock: sync.Mutex{},
	}

	go as.listenResponses(responses)
	return as
}

func (svc *adapterService) get(obsID string) (*Observer, bool) {
	svc.obsLock.Lock()
	defer svc.obsLock.Unlock()

	val, ok := svc.obs[obsID]
	return val, ok
}

func (svc *adapterService) put(obsID string, o *Observer) {
	svc.obsLock.Lock()
	defer svc.obsLock.Unlock()

	val, ok := svc.obs[obsID]
	if ok {
		close(val.Cancel)
	}

	svc.obs[obsID] = o
}

func (svc *adapterService) remove(obsID string) {
	svc.obsLock.Lock()
	defer svc.obsLock.Unlock()

	val, ok := svc.obs[obsID]
	if ok {
		close(val.Cancel)
		delete(svc.obs, obsID)
	}
}

// ListenResponses method handles ACK messages received from client.
func (svc *adapterService) listenResponses(responses <-chan string) {
	for {
		id := <-responses

		val, ok := svc.get(id)
		if ok {
			val.StoreExpired(false)
		}
	}
}

func (svc *adapterService) Publish(ctx context.Context, token string, msg mainflux.Message) error {
	if err := svc.pub.Publish(ctx, token, msg); err != nil {
		switch err {
		case nats.ErrConnectionClosed, nats.ErrInvalidConnection:
			return ErrFailedConnection
		default:
			return ErrFailedMessagePublish
		}
	}

	return nil
}

func (svc *adapterService) Subscribe(chanID, subtopic, obsID string, o *Observer) error {
	sub, err := svc.sub.Subscribe(chanID, subtopic, func(msg *nats.Msg) {
		if msg == nil {
			return
		}
		var m mainflux.Message
		if err := proto.Unmarshal(msg.Data, &m); err != nil {
			return
		}
		o.Messages <- m
	})
	if err != nil {
		return err
	}

	go func() {
		<-o.Cancel
		sub.Unsubscribe()
	}()

	// Put method removes Observer if already exists.
	svc.put(obsID, o)
	return nil
}

func (svc *adapterService) Unsubscribe(obsID string) {
	svc.remove(obsID)
}
