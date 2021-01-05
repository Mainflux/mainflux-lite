// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package notify

import "context"

// Subscription represents a user Subscription.
type Subscription struct {
	ID         string
	OwnerID    string
	OwnerEmail string
	Topic      string
}

// SubscriptionRepository specifies a Subscription persistence API.
type SubscriptionRepository interface {
	// Save persists a subscription. Successful operation is indicated by non-nil
	// error response.
	Save(ctx context.Context, sub Subscription) (string, error)

	// Retrieve retrieves the subscription for the given owner and topic.
	Retrieve(ctx context.Context, ownerID, topic string) error

	// Remove removes the subscription having the provided identifier, that is owned
	// by the specified user.
	RetrieveAll(ctx context.Context, topic string) ([]Subscription, error)

	// Remove removes the subscription having the provided identifier, that is owned
	// by the specified user.
	Remove(ctx context.Context, ownerID, id string) error
}