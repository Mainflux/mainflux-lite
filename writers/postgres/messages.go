// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"encoding/json"

	"github.com/gofrs/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq" // required for DB access
	"github.com/mainflux/mainflux/pkg/errors"
	mfjson "github.com/mainflux/mainflux/pkg/transformers/json"
	"github.com/mainflux/mainflux/pkg/transformers/senml"
	"github.com/mainflux/mainflux/writers"
)

const errInvalid = "invalid_text_representation"

var (
	// ErrInvalidMessage indicates that service received message that
	// doesn't fit required format.
	ErrInvalidMessage = errors.New("invalid message representation")
	errSaveMessage    = errors.New("failed to save message to postgres database")
	errTransRollback  = errors.New("failed to rollback transaction")
	errMessageFormat  = errors.New("invalid message format")
)

var _ writers.MessageRepository = (*postgresRepo)(nil)

type postgresRepo struct {
	db *sqlx.DB
}

// New returns new PostgreSQL writer.
func New(db *sqlx.DB) writers.MessageRepository {
	return &postgresRepo{db: db}
}

func (pr postgresRepo) Save(messages interface{}) (err error) {
	switch messages.(type) {
	case mfjson.Message:
		return pr.saveJSON(messages)
	default:
		return pr.saveSenml(messages)
	}
}

func (pr postgresRepo) saveSenml(messages interface{}) error {
	msgs, ok := messages.([]senml.Message)
	if !ok {
		return errSaveMessage
	}
	q := `INSERT INTO senml (id, channel, subtopic, publisher, protocol,
          name, unit, value, string_value, bool_value, data_value, sum,
          time, update_time)
          VALUES (:id, :channel, :subtopic, :publisher, :protocol, :name, :unit,
          :value, :string_value, :bool_value, :data_value, :sum,
          :time, :update_time);`

	tx, err := pr.db.BeginTxx(context.Background(), nil)
	if err != nil {
		return errors.Wrap(errSaveMessage, err)
	}
	defer func() {
		if err != nil {
			if txErr := tx.Rollback(); txErr != nil {
				err = errors.Wrap(err, errors.Wrap(errTransRollback, txErr))
			}
			return
		}

		if err = tx.Commit(); err != nil {
			err = errors.Wrap(errSaveMessage, err)
		}
		return
	}()

	for _, msg := range msgs {
		dbmsg, err := toSenmlMessage(msg)
		if err != nil {
			return errors.Wrap(errSaveMessage, err)
		}

		if _, err := tx.NamedExec(q, dbmsg); err != nil {
			pqErr, ok := err.(*pq.Error)
			if ok {
				switch pqErr.Code.Name() {
				case errInvalid:
					return errors.Wrap(errSaveMessage, ErrInvalidMessage)
				}
			}

			return errors.Wrap(errSaveMessage, err)
		}
	}
	return err
}

func (pr postgresRepo) saveJSON(messages interface{}) error {
	msgs := []mfjson.Message{}
	switch m := messages.(type) {
	case mfjson.Message:
		msgs = append(msgs, m)
	case []mfjson.Message:
		msgs = append(msgs, m...)
	default:
		return errMessageFormat
	}

	tx, err := pr.db.BeginTxx(context.Background(), nil)
	if err != nil {
		return errors.Wrap(errSaveMessage, err)
	}

	q := `INSERT INTO json (id, channel, subtopic, publisher, protocol, payload)
		  VALUES (:id, :channel, :subtopic, :publisher, :protocol, :payload);`

	defer func() {
		if err != nil {
			if txErr := tx.Rollback(); txErr != nil {
				err = errors.Wrap(err, errors.Wrap(errTransRollback, txErr))
			}
			return
		}

		if err = tx.Commit(); err != nil {
			err = errors.Wrap(errSaveMessage, err)
		}
		return
	}()

	for _, msg := range msgs {
		var dbmsg jsonMessage
		dbmsg, err = toJSONMessage(msg)
		if err != nil {
			return errors.Wrap(errSaveMessage, err)
		}
		if _, err = tx.NamedExec(q, dbmsg); err != nil {
			pqErr, ok := err.(*pq.Error)
			if ok {
				switch pqErr.Code.Name() {
				case errInvalid:
					return errors.Wrap(errSaveMessage, ErrInvalidMessage)
				}
			}

			return errors.Wrap(errSaveMessage, err)
		}
	}

	return err
}

type dbMessage struct {
	ID        string `db:"id"`
	Channel   string `db:"channel"`
	Subtopic  string `db:"subtopic"`
	Publisher string `db:"publisher"`
	Protocol  string `db:"protocol"`
}

type senmlMessage struct {
	dbMessage
	Name        string   `db:"name"`
	Unit        string   `db:"unit"`
	Value       *float64 `db:"value"`
	StringValue *string  `db:"string_value"`
	BoolValue   *bool    `db:"bool_value"`
	DataValue   *string  `db:"data_value"`
	Sum         *float64 `db:"sum"`
	Time        float64  `db:"time"`
	UpdateTime  float64  `db:"update_time"`
}

type jsonMessage struct {
	dbMessage
	Payload []byte `db:"payload"`
}

func toJSONMessage(msg mfjson.Message) (jsonMessage, error) {
	id, err := uuid.NewV4()
	if err != nil {
		return jsonMessage{}, err
	}

	data := []byte("{}")
	if len(msg.Payload) > 0 {
		b, err := json.Marshal(msg.Payload)
		if err != nil {
			return jsonMessage{}, errors.Wrap(errSaveMessage, err)
		}
		data = b
	}

	m := jsonMessage{
		dbMessage: dbMessage{
			ID:        id.String(),
			Channel:   msg.Channel,
			Subtopic:  msg.Subtopic,
			Publisher: msg.Publisher,
			Protocol:  msg.Protocol,
		},
		Payload: data,
	}

	return m, nil
}

func toSenmlMessage(msg senml.Message) (senmlMessage, error) {
	id, err := uuid.NewV4()
	if err != nil {
		return senmlMessage{}, err
	}

	m := senmlMessage{
		dbMessage: dbMessage{
			ID:        id.String(),
			Channel:   msg.Channel,
			Subtopic:  msg.Subtopic,
			Publisher: msg.Publisher,
			Protocol:  msg.Protocol,
		},
		Name:       msg.Name,
		Unit:       msg.Unit,
		Time:       msg.Time,
		UpdateTime: msg.UpdateTime,
		Sum:        msg.Sum,
	}

	switch {
	case msg.Value != nil:
		m.Value = msg.Value
	case msg.StringValue != nil:
		m.StringValue = msg.StringValue
	case msg.DataValue != nil:
		m.DataValue = msg.DataValue
	case msg.BoolValue != nil:
		m.BoolValue = msg.BoolValue
	}

	return m, nil
}
