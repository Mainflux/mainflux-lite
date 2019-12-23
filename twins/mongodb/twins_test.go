// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package mongodb_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	log "github.com/mainflux/mainflux/logger"
	"github.com/mainflux/mainflux/twins"
	"github.com/mainflux/mainflux/twins/mongodb"
	"github.com/mainflux/mainflux/twins/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	maxNameSize = 1024
	msgsNum     = 10
	testDB      = "test"
	collection  = "twins"
	email       = "mfx_twin@example.com"
	validName   = "mfx_twin"
)

var (
	port        string
	addr        string
	testLog, _  = log.New(os.Stdout, log.Info.String())
	idp         = uuid.New()
	db          mongo.Database
	invalidName = strings.Repeat("m", maxNameSize+1)
)

func TestTwinsSave(t *testing.T) {
	client, err := mongo.Connect(context.Background(), options.Client().ApplyURI(addr))
	require.Nil(t, err, fmt.Sprintf("Creating new MongoDB client expected to succeed: %s.\n", err))

	db := client.Database(testDB)
	repo := mongodb.NewTwinRepository(db)

	twid, err := idp.ID()
	require.Nil(t, err, fmt.Sprintf("got unexpected error: %s", err))
	twkey, err := idp.ID()
	require.Nil(t, err, fmt.Sprintf("got unexpected error: %s", err))

	nonexistentTwinID, err := idp.ID()
	require.Nil(t, err, fmt.Sprintf("got unexpected error: %s", err))

	nonexistentTwinKey, err := idp.ID()
	require.Nil(t, err, fmt.Sprintf("got unexpected error: %s", err))

	twin := twins.Twin{
		Owner: email,
		ID:    twid,
		Key:   twkey,
	}

	cases := []struct {
		desc string
		twin twins.Twin
		err  error
	}{
		{
			desc: "create new twin",
			twin: twin,
			err:  nil,
		},
		{
			desc: "create twin with existing ID",
			twin: twins.Twin{
				ID:    twid,
				Owner: email,
				Key:   nonexistentTwinKey,
			},
			err: twins.ErrConflict,
		},
		{
			desc: "create twin with existing Key",
			twin: twins.Twin{
				ID:    nonexistentTwinID,
				Owner: email,
				Key:   twkey,
			},
			err: twins.ErrConflict,
		},
		{
			desc: "create twin with invalid name",
			twin: twins.Twin{
				ID:    nonexistentTwinID,
				Owner: email,
				Key:   nonexistentTwinKey,
				Name:  invalidName,
			},
			err: twins.ErrMalformedEntity,
		},
	}

	for _, tc := range cases {
		_, err := repo.Save(context.Background(), tc.twin)
		assert.Equal(t, tc.err, err, fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
	}
}

func TestTwinsUpdate(t *testing.T) {
	client, err := mongo.Connect(context.Background(), options.Client().ApplyURI(addr))
	require.Nil(t, err, fmt.Sprintf("Creating new MongoDB client expected to succeed: %s.\n", err))

	db := client.Database(testDB)
	repo := mongodb.NewTwinRepository(db)

	twid, err := idp.ID()
	require.Nil(t, err, fmt.Sprintf("got unexpected error: %s", err))
	twkey, err := idp.ID()
	require.Nil(t, err, fmt.Sprintf("got unexpected error: %s", err))

	nonexistentTwinID, err := idp.ID()
	require.Nil(t, err, fmt.Sprintf("got unexpected error: %s", err))

	twin := twins.Twin{
		ID:   twid,
		Name: validName,
	}

	if _, err := repo.Save(context.Background(), twin); err != nil {
		testLog.Error(err.Error())
	}

	twin.Name = "new_name"
	cases := []struct {
		desc string
		twin twins.Twin
		err  error
	}{
		{
			desc: "update existing twin",
			twin: twin,
			err:  nil,
		},
		{
			desc: "update non-existing twin",
			twin: twins.Twin{
				ID: nonexistentTwinID,
			},
			err: twins.ErrNotFound,
		},
		{
			desc: "update twin with invalid name",
			twin: twins.Twin{
				ID:    twid,
				Owner: email,
				Key:   twkey,
				Name:  invalidName,
			},
			err: twins.ErrMalformedEntity,
		},
	}

	for _, tc := range cases {
		err := repo.Update(context.Background(), tc.twin)
		assert.Equal(t, tc.err, err, fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
	}
}

func TestTwinsRetrieveByID(t *testing.T) {
	client, err := mongo.Connect(context.Background(), options.Client().ApplyURI(addr))
	require.Nil(t, err, fmt.Sprintf("Creating new MongoDB client expected to succeed: %s.\n", err))

	db := client.Database(testDB)
	repo := mongodb.NewTwinRepository(db)

	twid, err := idp.ID()
	require.Nil(t, err, fmt.Sprintf("got unexpected error: %s", err))
	twkey, err := idp.ID()
	require.Nil(t, err, fmt.Sprintf("got unexpected error: %s", err))

	nonexistentTwinID, err := idp.ID()
	require.Nil(t, err, fmt.Sprintf("got unexpected error: %s", err))

	twin := twins.Twin{
		ID:  twid,
		Key: twkey,
	}

	if _, err := repo.Save(context.Background(), twin); err != nil {
		testLog.Error(err.Error())
	}

	cases := []struct {
		desc string
		id   string
		err  error
	}{
		{
			desc: "retrieve an existing twin",
			id:   twin.ID,
			err:  nil,
		},
		{
			desc: "retrieve a non-existing twin",
			id:   nonexistentTwinID,
			err:  twins.ErrNotFound,
		},
	}

	for _, tc := range cases {
		_, err := repo.RetrieveByID(context.Background(), tc.id)
		assert.Equal(t, tc.err, err, fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
	}
}

func TestTwinsRetrieveByKey(t *testing.T) {
	client, err := mongo.Connect(context.Background(), options.Client().ApplyURI(addr))
	require.Nil(t, err, fmt.Sprintf("Creating new MongoDB client expected to succeed: %s.\n", err))

	db := client.Database(testDB)
	repo := mongodb.NewTwinRepository(db)

	twid, err := idp.ID()
	require.Nil(t, err, fmt.Sprintf("got unexpected error: %s", err))
	twkey, err := idp.ID()
	require.Nil(t, err, fmt.Sprintf("got unexpected error: %s", err))

	nonexistentTwinKey, err := idp.ID()
	require.Nil(t, err, fmt.Sprintf("got unexpected error: %s", err))

	twin := twins.Twin{
		ID:  twid,
		Key: twkey,
	}

	if _, err := repo.Save(context.Background(), twin); err != nil {
		testLog.Error(err.Error())
	}

	cases := []struct {
		desc string
		id   string
		key  string
		err  error
	}{
		{
			desc: "retrieve an existing twin",
			id:   twin.ID,
			key:  twin.Key,
			err:  nil,
		},
		{
			desc: "retrieve a non-existing twin",
			id:   "",
			key:  nonexistentTwinKey,
			err:  twins.ErrNotFound,
		},
	}

	for _, tc := range cases {
		id, err := repo.RetrieveByKey(context.Background(), tc.key)
		assert.Equal(t, tc.err, err, fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		assert.Equal(t, id, tc.id, fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.id, id))
	}
}

func TestTwinsRetrieveByThing(t *testing.T) {
	client, err := mongo.Connect(context.Background(), options.Client().ApplyURI(addr))
	require.Nil(t, err, fmt.Sprintf("Creating new MongoDB client expected to succeed: %s.\n", err))

	db := client.Database(testDB)
	repo := mongodb.NewTwinRepository(db)

	twid, err := idp.ID()
	require.Nil(t, err, fmt.Sprintf("got unexpected error: %s", err))
	twkey, err := idp.ID()
	require.Nil(t, err, fmt.Sprintf("got unexpected error: %s", err))

	thingid, err := idp.ID()
	require.Nil(t, err, fmt.Sprintf("got unexpected error: %s", err))

	nonexistentThingID, err := idp.ID()
	require.Nil(t, err, fmt.Sprintf("got unexpected error: %s", err))

	twin := twins.Twin{
		ID:      twid,
		Key:     twkey,
		ThingID: thingid,
	}

	if _, err := repo.Save(context.Background(), twin); err != nil {
		testLog.Error(err.Error())
	}

	cases := []struct {
		desc    string
		thingid string
		err     error
	}{
		{
			desc:    "retrieve an existing twin",
			thingid: thingid,
			err:     nil,
		},
		{
			desc:    "retrieve a non-existing twin",
			thingid: nonexistentThingID,
			err:     twins.ErrNotFound,
		},
	}

	for _, tc := range cases {
		_, err := repo.RetrieveByThing(context.Background(), tc.thingid)
		assert.Equal(t, tc.err, err, fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
	}
}

func TestTwinsRetrieveAll(t *testing.T) {
	email := "twin-multi-retrieval@example.com"
	name := "mainflux"
	metadata := make(twins.Metadata)
	metadata["serial"] = "123456"
	metadata["type"] = "test"
	idp := uuid.New()

	client, err := mongo.Connect(context.Background(), options.Client().ApplyURI(addr))
	require.Nil(t, err, fmt.Sprintf("Creating new MongoDB client expected to succeed: %s.\n", err))

	db := client.Database(testDB)
	db.Collection(collection).DeleteMany(context.Background(), bson.D{})

	twinRepo := mongodb.NewTwinRepository(db)

	n := uint64(10)
	for i := uint64(0); i < n; i++ {
		twid, err := idp.ID()
		require.Nil(t, err, fmt.Sprintf("got unexpected error: %s", err))
		twkey, err := idp.ID()
		require.Nil(t, err, fmt.Sprintf("got unexpected error: %s", err))

		tw := twins.Twin{
			Owner:    email,
			ID:       twid,
			Key:      twkey,
			Metadata: metadata,
		}

		// Create first two Twins with name.
		if i < 2 {
			tw.Name = name
		}

		twinRepo.Save(context.Background(), tw)
	}

	cases := map[string]struct {
		owner    string
		limit    uint64
		offset   uint64
		name     string
		size     uint64
		total    uint64
		metadata twins.Metadata
	}{
		"retrieve all twins with existing owner": {
			owner:  email,
			offset: 0,
			limit:  n,
			size:   n,
			total:  n,
		},
		"retrieve subset of twins with existing owner": {
			owner:  email,
			offset: 0,
			limit:  n / 2,
			size:   n / 2,
			total:  n,
		},
		"retrieve twins with non-existing owner": {
			owner:  wrongValue,
			offset: 0,
			limit:  n,
			size:   0,
			total:  0,
		},
		"retrieve twins with existing name": {
			offset: 0,
			limit:  1,
			name:   name,
			size:   1,
			total:  2,
		},
		"retrieve twins with non-existing name": {
			offset: 0,
			limit:  n,
			name:   "wrong",
			size:   0,
			total:  0,
		},
		// "retrieve twins with metadata": {
		// 	offset:   0,
		// 	limit:    n,
		// 	size:     n,
		// 	total:    n,
		// 	metadata: metadata,
		// },
	}

	for desc, tc := range cases {
		page, err := twinRepo.RetrieveAll(context.Background(), tc.owner, tc.offset, tc.limit, tc.name, tc.metadata)
		size := uint64(len(page.Twins))
		assert.Equal(t, tc.size, size, fmt.Sprintf("%s: expected %d got %d\n", desc, tc.size, size))
		assert.Equal(t, tc.total, page.Total, fmt.Sprintf("%s: expected %d got %d\n", desc, tc.total, page.Total))
		assert.Nil(t, err, fmt.Sprintf("%s: expected no error got %d\n", desc, err))
	}
}

func TestTwinsRemove(t *testing.T) {
	client, err := mongo.Connect(context.Background(), options.Client().ApplyURI(addr))
	require.Nil(t, err, fmt.Sprintf("Creating new MongoDB client expected to succeed: %s.\n", err))

	db := client.Database(testDB)
	repo := mongodb.NewTwinRepository(db)

	twid, err := idp.ID()
	require.Nil(t, err, fmt.Sprintf("got unexpected error: %s", err))

	nonexistentTwinID, err := idp.ID()
	require.Nil(t, err, fmt.Sprintf("got unexpected error: %s", err))

	twin := twins.Twin{
		ID: twid,
	}

	if _, err := repo.Save(context.Background(), twin); err != nil {
		testLog.Error(err.Error())
	}

	cases := []struct {
		desc string
		id   string
		err  error
	}{
		{
			desc: "remove an existing twin",
			id:   twin.ID,
			err:  nil,
		},
		{
			desc: "remove a non-existing twin",
			id:   nonexistentTwinID,
			err:  twins.ErrNotFound,
		},
	}

	for _, tc := range cases {
		err := repo.Remove(context.Background(), tc.id)
		assert.Equal(t, tc.err, err, fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
	}
}
