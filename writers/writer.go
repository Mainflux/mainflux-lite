// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package writers

import (
	"fmt"
	"io/ioutil"

	"github.com/BurntSushi/toml"
	"github.com/mainflux/mainflux"
	"github.com/mainflux/mainflux/errors"
	"github.com/mainflux/mainflux/logger"
	"github.com/mainflux/mainflux/nats"
	"github.com/mainflux/mainflux/transformers"
	"github.com/mainflux/mainflux/transformers/senml"
	broker "github.com/nats-io/nats.go"
)

var (
	errOpenConfFile      = errors.New("unable to open configuration file")
	errParseConfFile     = errors.New("unable to parse configuration file")
	errMessageConversion = errors.New("error conversing transformed messages")
)

type consumer struct {
	repo        MessageRepository
	transformer transformers.Transformer
	logger      logger.Logger
}

// Start method starts consuming messages received from NATS.
// This method transforms messages to SenML format before
// using MessageRepository to store them.
func Start(conn *broker.Conn, repo MessageRepository, transformer transformers.Transformer, queue string, subjectsCfgPath string, logger logger.Logger) error {
	c := consumer{
		repo:        repo,
		transformer: transformer,
		logger:      logger,
	}

	subjects, err := loadSubjectsConfig(subjectsCfgPath)
	if err != nil {
		logger.Warn(fmt.Sprintf("Failed to load subjects: %s", err))
	}

	for _, subject := range subjects {
		sub := nats.New(conn, subject, queue, logger)
		if err := sub.Subscribe(c.handler); err != nil {
			return err
		}
	}
	return nil
}

func (c *consumer) handler(msg mainflux.Message) error {
	t, err := c.transformer.Transform(msg)
	if err != nil {
		return err
	}
	msgs, ok := t.([]senml.Message)
	if !ok {
		return errMessageConversion
	}

	return c.repo.Save(msgs...)
}

type filterConfig struct {
	List []string `toml:"filter"`
}

type subjectsConfig struct {
	Subjects filterConfig `toml:"subjects"`
}

func loadSubjectsConfig(subjectsConfigPath string) ([]string, error) {
	data, err := ioutil.ReadFile(subjectsConfigPath)
	if err != nil {
		return []string{nats.SubjectAllChannels}, errors.Wrap(errOpenConfFile, err)
	}

	var subjectsCfg subjectsConfig
	if err := toml.Unmarshal(data, &subjectsCfg); err != nil {
		return []string{nats.SubjectAllChannels}, errors.Wrap(errParseConfFile, err)
	}

	return subjectsCfg.Subjects.List, nil
}
