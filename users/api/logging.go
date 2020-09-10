// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"fmt"
	"time"

	log "github.com/mainflux/mainflux/logger"
	"github.com/mainflux/mainflux/users"
)

var _ users.Service = (*loggingMiddleware)(nil)

type loggingMiddleware struct {
	logger log.Logger
	svc    users.Service
}

// LoggingMiddleware adds logging facilities to the core service.
func LoggingMiddleware(svc users.Service, logger log.Logger) users.Service {
	return &loggingMiddleware{logger, svc}
}

func (lm *loggingMiddleware) Register(ctx context.Context, user users.User) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method register for user %s took %s to complete", user.Email, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))

	}(time.Now())

	return lm.svc.Register(ctx, user)
}

func (lm *loggingMiddleware) Login(ctx context.Context, user users.User) (token string, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method login for user %s took %s to complete", user.Email, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.Login(ctx, user)
}

func (lm *loggingMiddleware) ViewUser(ctx context.Context, token string) (u users.User, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method view_user for user %s took %s to complete", u.Email, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.ViewUser(ctx, token)
}

func (lm *loggingMiddleware) UpdateUser(ctx context.Context, token string, u users.User) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method update_user for user %s took %s to complete", u.Email, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.UpdateUser(ctx, token, u)
}

func (lm *loggingMiddleware) GenerateResetToken(ctx context.Context, email, host string) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method generate_reset_token for user %s took %s to complete", email, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.GenerateResetToken(ctx, email, host)
}

func (lm *loggingMiddleware) ChangePassword(ctx context.Context, email, password, oldPassword string) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method change_password for user %s took %s to complete", email, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.ChangePassword(ctx, email, password, oldPassword)
}

func (lm *loggingMiddleware) ResetPassword(ctx context.Context, email, password string) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method reset_password for user %s took %s to complete", email, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.ResetPassword(ctx, email, password)
}

func (lm *loggingMiddleware) SendPasswordReset(ctx context.Context, host, email, token string) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method send_password_reset for user %s took %s to complete", email, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.SendPasswordReset(ctx, host, email, token)
}

func (lm *loggingMiddleware) CreateGroup(ctx context.Context, token string, group users.Group) (users.Group, error) {
	return lm.svc.CreateGroup(ctx, token, group)
}

func (lm *loggingMiddleware) ListGroups(ctx context.Context, token string, offset, limit uint64, id string, meta users.Metadata) (users.GroupPage, error) {
	return lm.svc.ListGroups(ctx, token, offset, limit, id, meta)
}

func (lm *loggingMiddleware) RemoveGroup(ctx context.Context, token, id string) error {
	return lm.svc.RemoveGroup(ctx, token, id)
}

func (lm *loggingMiddleware) UpdateGroup(ctx context.Context, token string, group users.Group) error {
	return lm.svc.UpdateGroup(ctx, token, group)
}

func (lm *loggingMiddleware) ViewGroup(ctx context.Context, token, id string) (users.Group, error) {
	return lm.svc.ViewGroup(ctx, token, id)
}

func (lm *loggingMiddleware) AssignUserToGroup(ctx context.Context, token, userId, groupId string) error {
	return lm.svc.AssignUserToGroup(ctx, token, userId, groupId)
}

func (lm *loggingMiddleware) RemoveUserFromGroup(ctx context.Context, token, userID, groupID string) error {
	return lm.svc.RemoveUserFromGroup(ctx, token, userID, groupID)
}
