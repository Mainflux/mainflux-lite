//
// Copyright (c) 2018
// Mainflux
//
// SPDX-License-Identifier: Apache-2.0
//

package influxdb_test

import (
	"fmt"
	"os"
	"testing"
	"time"

	influxdata "github.com/influxdata/influxdb/client/v2"
	"github.com/mainflux/mainflux"
	log "github.com/mainflux/mainflux/logger"
	"github.com/mainflux/mainflux/writers"
	writer "github.com/mainflux/mainflux/writers/influxdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const logLevel = "info"

var (
	port          string
	testLog       = log.New(os.Stdout, logLevel)
	testDB        = "test"
	saveTimeout   = 2 * time.Second
	saveBatchSize = 20
	streamsSize   = 250
	client        influxdata.Client
	selectMsgs    = fmt.Sprintf("SELECT * FROM test..messages")
	dropMsgs      = fmt.Sprintf("DROP SERIES FROM messages")
	clientCfg     = influxdata.HTTPConfig{
		Username: "test",
		Password: "test",
	}

	msg = mainflux.Message{
		Channel:     45,
		Publisher:   2580,
		Protocol:    "http",
		Name:        "test name",
		Unit:        "km",
		Value:       24,
		StringValue: "24",
		BoolValue:   false,
		DataValue:   "dataValue",
		ValueSum:    24,
		Time:        13451312,
		UpdateTime:  5456565466,
		Link:        "link",
	}
)

// This is utility function to query the database.
func queryDB(cmd string) ([][]interface{}, error) {
	q := influxdata.Query{
		Command:  cmd,
		Database: testDB,
	}
	response, err := client.Query(q)
	if err != nil {
		return nil, err
	}
	if response.Error() != nil {
		return nil, response.Error()
	}
	if len(response.Results[0].Series) == 0 {
		return nil, nil
	}
	// There is only one query, so only one result and
	// all data are stored in the same series.
	return response.Results[0].Series[0].Values, nil
}

func TestSave(t *testing.T) {
	client, err := influxdata.NewHTTPClient(clientCfg)
	require.Nil(t, err, fmt.Sprintf("Creating new InfluxDB client expected to succeed: %s.\n", err))

	// Set batch size to 1 to simulate single point insert.
	repo, err := writer.New(client, testDB, 1, saveTimeout)
	require.Nil(t, err, fmt.Sprintf("Creating new InfluxDB repo expected to succeed: %s.\n", err))

	// Set batch size to value > 1 to simulate real batch.
	repo1, err := writer.New(client, testDB, saveBatchSize, saveTimeout)
	require.Nil(t, err, fmt.Sprintf("Creating new InfluxDB repo expected to succeed: %s.\n", err))

	cases := []struct {
		desc         string
		repo         writers.MessageRepository
		previousMsgs int
		numOfMsg     int
		expectedSize int
		isBatch      bool
	}{
		{
			desc:         "save a single message",
			repo:         repo,
			numOfMsg:     1,
			expectedSize: 1,
			isBatch:      false,
		},
		{
			desc:         "save a batch of messages",
			repo:         repo1,
			numOfMsg:     streamsSize,
			expectedSize: streamsSize - (streamsSize % saveBatchSize),
			isBatch:      true,
		},
	}

	for _, tc := range cases {
		// Clean previously saved messages.
		row, err := queryDB(dropMsgs)
		require.Nil(t, err, fmt.Sprintf("Cleaning data from InfluxDB expected to succeed: %s.\n", err))

		for i := 0; i < tc.numOfMsg; i++ {
			err := tc.repo.Save(msg)
			assert.Nil(t, err, fmt.Sprintf("Save operation expected to succeed: %s.\n", err))
		}

		row, err = queryDB(selectMsgs)
		assert.Nil(t, err, fmt.Sprintf("Querying InfluxDB to retrieve data expected to succeed: %s.\n", err))

		count := len(row)
		assert.Equal(t, tc.expectedSize, count, fmt.Sprintf("Expected to have %d messages saved, found %d instead.\n", tc.expectedSize, count))

		if tc.isBatch {
			// Sleep for `saveBatchTime` to trigger ticker and check if the reset of the data is saved.
			time.Sleep(saveTimeout)

			row, err = queryDB(selectMsgs)
			assert.Nil(t, err, fmt.Sprintf("Querying InfluxDB to retrieve data count expected to succeed: %s.\n", err))
			count = len(row)
			assert.Equal(t, tc.numOfMsg, count, fmt.Sprintf("Expected to have %d messages, found %d instead.\n", tc.numOfMsg, count))
		}
	}
}
