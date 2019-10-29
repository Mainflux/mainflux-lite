// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package normalizer

import (
	"github.com/cisco/senml"
	"github.com/mainflux/mainflux"
)

// Normalize takes a RawMessage and converts
// it to an array of the Mainflux message.
func Normalize(msg mainflux.RawMessage) ([]mainflux.Message, error) {
	format, ok := formats[msg.ContentType]
	if !ok {
		format = senml.JSON
	}

	raw, err := senml.Decode(msg.Payload, format)
	if err != nil {
		return []mainflux.Message{}, err
	}

	normalized := senml.Normalize(raw)

	msgs := make([]mainflux.Message, len(normalized.Records))
	for k, v := range normalized.Records {
		m := mainflux.Message{
			Channel:    msg.Channel,
			Subtopic:   msg.Subtopic,
			Publisher:  msg.Publisher,
			Protocol:   msg.Protocol,
			Name:       v.Name,
			Unit:       v.Unit,
			Time:       v.Time,
			UpdateTime: v.UpdateTime,
			Link:       v.Link,
		}

		switch {
		case v.Value != nil:
			m.Value = &mainflux.Message_FloatValue{FloatValue: *v.Value}
		case v.BoolValue != nil:
			m.Value = &mainflux.Message_BoolValue{BoolValue: *v.BoolValue}
		case v.DataValue != "":
			m.Value = &mainflux.Message_DataValue{DataValue: v.DataValue}
		case v.StringValue != "":
			m.Value = &mainflux.Message_StringValue{StringValue: v.StringValue}
		}

		if v.Sum != nil {
			m.ValueSum = &mainflux.SumValue{Value: *v.Sum}
		}

		msgs[k] = m
	}

	return msgs, nil
}

var formats = map[string]senml.Format{
	mainflux.SenMLJSON: senml.JSON,
	mainflux.SenMLCBOR: senml.CBOR,
}
