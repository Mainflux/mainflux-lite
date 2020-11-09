// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package json

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/mainflux/mainflux/pkg/messaging"
	"github.com/mainflux/mainflux/pkg/transformers"
)

const sep = "/"

var (
	// ErrInvalidKey represents an invalid JSON key format.
	ErrInvalidKey = errors.New("invalid object key")

	errInvalidFormat     = errors.New("invalid JSON object")
	errInvalidNestedJSON = errors.New("invalid nested JSON object")
)

type funcTransformer func(messaging.Message) (interface{}, error)

// New returns a new JSON transformer.
func New() transformers.Transformer {
	return funcTransformer(transformer)
}

func (fh funcTransformer) Transform(msg messaging.Message) (interface{}, error) {
	return fh(msg)
}
func transformer(msg messaging.Message) (interface{}, error) {
	ret := Message{
		Publisher: msg.Publisher,
		Created:   msg.Created,
		Protocol:  msg.Protocol,
		Channel:   msg.Channel,
		Subtopic:  msg.Subtopic,
	}
	var payload interface{}
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		return nil, err
	}
	switch p := payload.(type) {
	case map[string]interface{}:
		pld := make(map[string]interface{})
		flat, err := flatten("", pld, p)
		if err != nil {
			return nil, err
		}
		ret.Payload = flat
		return ret, nil
	case []interface{}:
		res := []Message{}
		// Make an array of messages from the root array.
		for _, val := range p {
			v, ok := val.(map[string]interface{})
			if !ok {
				return nil, errInvalidNestedJSON
			}
			pld := make(map[string]interface{})
			flat, err := flatten("", pld, v)
			if err != nil {
				return nil, err
			}
			newMsg := ret
			newMsg.Payload = flat
			res = append(res, newMsg)
		}
		return res, nil
	default:
		return nil, errInvalidFormat
	}
}

func flatten(prefix string, m, m1 map[string]interface{}) (map[string]interface{}, error) {
	for k, v := range m1 {
		if k == "publisher" || k == "protocol" || k == "channel" || k == "subtopic" || strings.Contains(k, sep) {
			return nil, ErrInvalidKey
		}
		switch val := v.(type) {
		case map[string]interface{}:
			var err error
			m, err = flatten(prefix+k+sep, m, val)
			if err != nil {
				return nil, err
			}
		default:
			m[prefix+k] = v
		}
	}
	return m, nil
}
