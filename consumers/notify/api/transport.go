// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	"github.com/mainflux/mainflux/consumers/notify"
	"github.com/mainflux/mainflux/pkg/errors"

	kitot "github.com/go-kit/kit/tracing/opentracing"
	kithttp "github.com/go-kit/kit/transport/http"
	"github.com/go-zoo/bone"
	"github.com/mainflux/mainflux"
	opentracing "github.com/opentracing/opentracing-go"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	contentType = "application/json"

	offsetKey   = "offset"
	limitKey    = "limit"
	nameKey     = "name"
	emailKey    = "email"
	metadataKey = "metadata"

	defOffset = 0
	defLimit  = 10
)

var (
	errMalformedEntity    = errors.New("failed to decode request body")
	errInvalidQueryParams = errors.New("invalid query parameters")
)

// MakeHandler returns a HTTP handler for API endpoints.
func MakeHandler(svc notify.Service, tracer opentracing.Tracer) http.Handler {
	opts := []kithttp.ServerOption{
		kithttp.ServerErrorEncoder(encodeError),
	}

	mux := bone.New()

	mux.Post("/subscriptions/:topic", kithttp.NewServer(
		kitot.TraceServer(tracer, "create_subscription")(createSubscriptionEndpoint(svc)),
		decodeCreate,
		encodeResponse,
		opts...,
	))

	mux.Get("/subscriptions/:id", kithttp.NewServer(
		kitot.TraceServer(tracer, "view_subscription")(viewSubscriptionEndpint(svc)),
		decodeSubscription,
		encodeResponse,
		opts...,
	))

	mux.Get("/subscriptions", kithttp.NewServer(
		kitot.TraceServer(tracer, "list_subscriptions")(listSubscriptionsEndpoint(svc)),
		decodeList,
		encodeResponse,
		opts...,
	))

	mux.Delete("/subscriptions/:id", kithttp.NewServer(
		kitot.TraceServer(tracer, "delete_group")(deleteSubscriptionEndpint(svc)),
		decodeSubscription,
		encodeResponse,
		opts...,
	))

	mux.GetFunc("/version", mainflux.Version("notifier"))
	mux.Handle("/metrics", promhttp.Handler())

	return mux
}

func decodeCreate(_ context.Context, r *http.Request) (interface{}, error) {
	req := createSubReq{
		Topic: bone.GetValue(r, "topic"),
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, errors.Wrap(errMalformedEntity, err)
	}

	req.token = r.Header.Get("Authorization")
	return req, nil
}

func decodeSubscription(_ context.Context, r *http.Request) (interface{}, error) {
	req := subReq{
		id:    bone.GetValue(r, "id"),
		token: r.Header.Get("Authorization"),
	}

	return req, nil
}

func decodeList(_ context.Context, r *http.Request) (interface{}, error) {
	req := listSubsReq{
		token: r.Header.Get("Authorization"),
	}
	vals := bone.GetQuery(r, "topic")
	if len(vals) > 0 {
		req.topic = vals[0]
	}

	vals = bone.GetQuery(r, "contact")
	if len(vals) > 0 {
		req.contact = vals[0]
	}

	offset, err := readUintQuery(r, "offset", 0)
	if err != nil {
		return listSubsReq{}, err
	}
	req.offset = offset

	limit, err := readUintQuery(r, "limit", 10)
	if err != nil {
		return listSubsReq{}, err
	}
	req.limit = limit

	return req, nil
}

func readUintQuery(r *http.Request, key string, def uint) (uint, error) {
	vals := bone.GetQuery(r, key)
	if len(vals) > 1 {
		return 0, errInvalidQueryParams
	}

	if len(vals) == 0 {
		return def, nil
	}

	strval := vals[0]
	val, err := strconv.ParseUint(strval, 10, 64)
	if err != nil {
		return 0, errInvalidQueryParams
	}

	return uint(val), nil

}
func encodeResponse(_ context.Context, w http.ResponseWriter, response interface{}) error {
	if ar, ok := response.(mainflux.Response); ok {
		for k, v := range ar.Headers() {
			w.Header().Set(k, v)
		}
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(ar.Code())

		if ar.Empty() {
			return nil
		}
	}

	return json.NewEncoder(w).Encode(response)
}

func encodeError(_ context.Context, err error, w http.ResponseWriter) {
	switch errorVal := err.(type) {
	case errors.Error:
		w.Header().Set("Content-Type", contentType)
		switch {
		case errors.Contains(errorVal, errMalformedEntity):
			w.WriteHeader(http.StatusBadRequest)
		case errors.Contains(errorVal, notify.ErrUnauthorizedAccess):
			w.WriteHeader(http.StatusUnauthorized)
		case errors.Contains(errorVal, notify.ErrConflict):
			w.WriteHeader(http.StatusConflict)
		case errors.Contains(errorVal, io.ErrUnexpectedEOF):
			w.WriteHeader(http.StatusBadRequest)
		case errors.Contains(errorVal, io.EOF):
			w.WriteHeader(http.StatusBadRequest)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
		if errorVal.Msg() != "" {
			if err := json.NewEncoder(w).Encode(errorRes{Err: errorVal.Msg()}); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
			}
		}
	default:
		w.WriteHeader(http.StatusInternalServerError)
	}
}
