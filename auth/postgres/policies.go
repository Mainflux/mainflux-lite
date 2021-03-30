package postgres

import (
	"context"

	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/mainflux/mainflux/auth"
	"github.com/mainflux/mainflux/pkg/errors"
)

func (gr groupRepository) SavePolicy(ctx context.Context, p auth.Policy) (auth.Policy, error) {
	// For root group path is initialized with id
	q := `INSERT INTO policy (id, description, subject, subject_id, object, object_id, action, created_at, updated_at) 
		  VALUES (:id, :description, :subject, :subject_id, :object, :object_id, :action :created_at, :updated_at) 
		  RETURNING id, description, subject, subject_id, object, object_id, action, created_at, updated_at`

	row, err := gr.db.NamedQueryContext(ctx, q, p)
	if err != nil {
		pqErr, ok := err.(*pq.Error)
		if ok {
			switch pqErr.Code.Name() {
			case errInvalid, errTruncation:
				return auth.Policy{}, errors.Wrap(auth.ErrMalformedEntity, err)
			case errFK:
				return auth.Policy{}, errors.Wrap(auth.ErrCreateGroup, err)
			case errDuplicate:
				return auth.Policy{}, errors.Wrap(auth.ErrGroupConflict, err)
			}
		}

		return auth.Policy{}, errors.Wrap(auth.ErrCreateGroup, errors.New(pqErr.Message))
	}

	defer row.Close()
	row.Next()
	p = auth.Policy{}
	if err := row.StructScan(&p); err != nil {
		return auth.Policy{}, err
	}
	return p, nil
}

func (gr groupRepository) RetrievePolicy(ctx context.Context, p auth.Policy) (map[string]interface{}, error) {
	q := `SELECT id, description, subject, subject_id, object, object_id, action, created_at, updated_at FROM policies 
					  WHERE subject = :subject, subject_id = :subject_id, object = :object , object_id = :object_id 
					  GROUP BY subject, subject_id, object, object_id`

	rows, err := gr.db.NamedQueryContext(ctx, q, p)
	if err != nil {
		return map[string]interface{}{}, errors.Wrap(auth.ErrFailedToRetrievePolicy, err)
	}
	defer rows.Close()

	items, err := gr.processPolicyRows(rows)
	if err != nil {
		return map[string]interface{}{}, errors.Wrap(auth.ErrFailedToRetrievePolicy, err)
	}

	return items, nil
}

func (gr groupRepository) processPolicyRows(rows *sqlx.Rows) (map[string]interface{}, error) {
	var items map[string]interface{}
	var subjects map[string]map[string]auth.Policy

	for rows.Next() {
		p := auth.Policy{}
		if err := rows.StructScan(&p); err != nil {
			return items, err
		}

		s, ok := subjects[p.Subject]
		if !ok {
			subjects[p.Subject] = make(map[string]auth.Policy)
		}
		sub, ok := s[p.SubjectID]
		if !ok {
			s[p.SubjectID] = p
		}
		sub.Actions = append(sub.Actions, p.Actions...)
	}

	for key, s := range subjects {
		items[key] = s
	}

	return items, nil
}
