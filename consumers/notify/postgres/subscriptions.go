// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/lib/pq"
	"github.com/mainflux/mainflux/consumers/notify"
	"github.com/mainflux/mainflux/pkg/errors"
)

var _ notify.SubscriptionsRepository = (*subscriptionsRepo)(nil)

const errDuplicate = "unique_violation"

type subscriptionsRepo struct {
	db Database
}

// New instantiates a PostgreSQL implementation of Subscriptions repository.
func New(db Database) notify.SubscriptionsRepository {
	return &subscriptionsRepo{
		db: db,
	}
}

func (repo subscriptionsRepo) Save(ctx context.Context, sub notify.Subscription) (string, error) {
	q := `INSERT INTO subscriptions (id, owner_id, contact, topic) VALUES (:id, :owner_id, :contact, :topic) RETURNING id`

	dbSub := dbSubscription{
		ID:      sub.ID,
		OwnerID: sub.OwnerID,
		Contact: sub.Contact,
		Topic:   sub.Topic,
	}

	row, err := repo.db.NamedQueryContext(ctx, q, dbSub)
	if err != nil {
		if pqErr, ok := err.(*pq.Error); ok && pqErr.Code.Name() == errDuplicate {
			return "", errors.Wrap(notify.ErrConflict, err)
		}
		return "", errors.Wrap(notify.ErrSave, err)
	}
	defer row.Close()

	return sub.ID, nil
}

func (repo subscriptionsRepo) Retrieve(ctx context.Context, id string) (notify.Subscription, error) {
	q := `SELECT id, owner_id, contact, topic FROM subscriptions WHERE id = $1`
	sub := dbSubscription{}
	if err := repo.db.QueryRowxContext(ctx, q, id).StructScan(&sub); err != nil {
		if err == sql.ErrNoRows {
			return notify.Subscription{}, errors.Wrap(notify.ErrNotFound, err)

		}
		return notify.Subscription{}, errors.Wrap(notify.ErrSelectEntity, err)
	}

	return fromDBSub(sub), nil
}

func (repo subscriptionsRepo) RetrieveAll(ctx context.Context, pm notify.PageMetadata) (notify.Page, error) {
	q := `SELECT id, owner_id, contact, topic FROM subscriptions`
	args := make(map[string]interface{})
	if pm.Topic != "" {
		args["topic"] = pm.Topic
	}
	if pm.Contact != "" {
		args["contact"] = pm.Contact
	}
	var condition string
	if len(args) > 0 {
		var cond []string
		for k := range args {
			cond = append(cond, fmt.Sprintf("%s = :%s", k, k))
		}
		condition = fmt.Sprintf(" WHERE %s", strings.Join(cond, " AND "))
		q = fmt.Sprintf("%s%s", q, condition)
	}
	args["offset"] = pm.Offset
	q = fmt.Sprintf("%s OFFSET :offset", q)
	if pm.Limit > 0 {
		q = fmt.Sprintf("%s LIMIT :limit", q)
		args["limit"] = pm.Limit
	}

	rows, err := repo.db.NamedQueryContext(ctx, q, args)
	if err != nil {
		return notify.Page{}, errors.Wrap(notify.ErrSelectEntity, err)
	}
	defer rows.Close()

	var subs []notify.Subscription
	for rows.Next() {
		sub := dbSubscription{}
		if err := rows.StructScan(&sub); err != nil {
			return notify.Page{}, errors.Wrap(notify.ErrSelectEntity, err)
		}
		subs = append(subs, fromDBSub(sub))
	}

	if len(subs) == 0 {
		return notify.Page{}, notify.ErrNotFound
	}

	cq := fmt.Sprintf(`SELECT COUNT(*) FROM subscriptions %s`, condition)
	total, err := total(ctx, repo.db, cq, args)
	if err != nil {
		return notify.Page{}, errors.Wrap(notify.ErrSelectEntity, err)
	}

	ret := notify.Page{
		PageMetadata:  pm,
		Total:         total,
		Subscriptions: subs,
	}

	return ret, nil
}

func (repo subscriptionsRepo) Remove(ctx context.Context, id string) error {
	q := `DELETE from subscriptions WHERE id = $1`

	if r := repo.db.QueryRowxContext(ctx, q, id); r.Err() != nil {
		return errors.Wrap(notify.ErrRemoveEntity, r.Err())
	}
	return nil
}

func total(ctx context.Context, db Database, query string, params interface{}) (uint, error) {
	rows, err := db.NamedQueryContext(ctx, query, params)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	var total uint
	if rows.Next() {
		if err := rows.Scan(&total); err != nil {
			return 0, err
		}
	}
	return total, nil
}

type dbSubscription struct {
	ID      string `db:"id"`
	OwnerID string `db:"owner_id"`
	Contact string `db:"contact"`
	Topic   string `db:"topic"`
}

func fromDBSub(sub dbSubscription) notify.Subscription {
	return notify.Subscription{
		ID:      sub.ID,
		OwnerID: sub.OwnerID,
		Contact: sub.Contact,
		Topic:   sub.Topic,
	}
}