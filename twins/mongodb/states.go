// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package mongodb

import (
	"context"

	"github.com/mainflux/mainflux/twins"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	statesCollection string = "states"
)

type stateRepository struct {
	db *mongo.Database
}

var _ twins.StateRepository = (*stateRepository)(nil)

// NewStateRepository instantiates a MongoDB implementation of state
// repository.
func NewStateRepository(db *mongo.Database) twins.StateRepository {
	return &stateRepository{
		db: db,
	}
}

// SaveState persists the state
func (sr *stateRepository) Save(ctx context.Context, st twins.State) error {
	coll := sr.db.Collection(statesCollection)

	if _, err := coll.InsertOne(context.Background(), st); err != nil {
		return err
	}

	return nil
}

// CountStates returns the number of states related to twin
func (sr *stateRepository) Count(ctx context.Context, tw twins.Twin) (int64, error) {
	coll := sr.db.Collection(statesCollection)

	filter := bson.D{{"twinid", tw.ID}}
	total, err := coll.CountDocuments(ctx, filter)
	if err != nil {
		return 0, err
	}

	return total, nil
}

func decodeStates(ctx context.Context, cur *mongo.Cursor) ([]twins.State, error) {
	defer cur.Close(ctx)

	var results []twins.State
	for cur.Next(ctx) {
		var elem twins.State
		err := cur.Decode(&elem)
		if err != nil {
			return []twins.State{}, nil
		}
		results = append(results, elem)
	}

	if err := cur.Err(); err != nil {
		return []twins.State{}, nil
	}
	return results, nil
}

// RetrieveAll retrieves the subset of staes related to twin specified by id
func (sr *stateRepository) RetrieveAll(ctx context.Context, offset uint64, limit uint64, id string) (twins.StatesPage, error) {
	coll := sr.db.Collection(statesCollection)

	findOptions := options.Find()
	findOptions.SetSkip(int64(offset))
	findOptions.SetLimit(int64(limit))

	filter := bson.D{{"twinid", id}}

	cur, err := coll.Find(ctx, filter, findOptions)
	if err != nil {
		return twins.StatesPage{}, err
	}

	results, err := decodeStates(ctx, cur)
	if err != nil {
		return twins.StatesPage{}, err
	}

	total, err := coll.CountDocuments(ctx, filter)
	if err != nil {
		return twins.StatesPage{}, err
	}

	return twins.StatesPage{
		States: results,
		PageMetadata: twins.PageMetadata{
			Total:  uint64(total),
			Offset: offset,
			Limit:  limit,
		},
	}, nil
}

// RetrieveLast returns the last state related to twin spec by id
func (sr *stateRepository) RetrieveLast(ctx context.Context, id string) (twins.State, error) {
	coll := sr.db.Collection(statesCollection)

	filter := bson.D{{"twinid", id}}
	total, err := coll.CountDocuments(ctx, filter)
	if err != nil {
		return twins.State{}, err
	}

	findOptions := options.Find()
	var skip int64
	if total > 0 {
		skip = total - 1
	}
	findOptions.SetSkip(skip)
	findOptions.SetLimit(1)

	cur, err := coll.Find(ctx, filter, findOptions)
	if err != nil {
		return twins.State{}, err
	}

	results, err := decodeStates(ctx, cur)
	if err != nil {
		return twins.State{}, err
	}

	if len(results) < 1 {
		return twins.State{}, nil
	}
	return results[0], nil
}