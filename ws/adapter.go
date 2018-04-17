package ws

import (
	"errors"

	"github.com/mainflux/mainflux"
	broker "github.com/nats-io/go-nats"
)

var _ Service = (*adapterService)(nil)

var (
	// ErrFailedMessagePublish indicates that message publishing failed.
	ErrFailedMessagePublish = errors.New("failed to publish message")
	// ErrFailedSubscription indicates that client couldn't subscribe to specified channel.
	ErrFailedSubscription = errors.New("failed to subscribe to a channel")
	// ErrFailedConnection indicates that service couldn't connect to message broker.
	ErrFailedConnection = errors.New("failed to connect to message broker")
)

// Service specifies web socket service API.
type Service interface {
	mainflux.MessagePublisher
	// Subscribes to channel with specified id.
	Subscribe(string, Channel) error
}

type adapterService struct {
	pubsub Service
}

// New instantiates the domain service implementation.
func New(pubsub Service) Service {
	return &adapterService{pubsub}
}

func (as *adapterService) Publish(msg mainflux.RawMessage) error {
	if err := as.pubsub.Publish(msg); err != nil {
		switch err {
		case broker.ErrConnectionClosed, broker.ErrInvalidConnection:
			return ErrFailedConnection
		default:
			return ErrFailedMessagePublish
		}
	}
	return nil
}

func (as *adapterService) Subscribe(chanID string, channel Channel) error {
	if err := as.pubsub.Subscribe(chanID, channel); err != nil {
		return ErrFailedSubscription
	}
	return nil
}

// Channel is used for recieving and sending messages.
type Channel struct {
	Messages chan mainflux.RawMessage
	Closed   chan bool
}

// Close channel and stop message transfer.
func (channel Channel) Close() {
	close(channel.Messages)
	close(channel.Closed)
}
