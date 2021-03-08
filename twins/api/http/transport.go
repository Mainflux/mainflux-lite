// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package http

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	kitot "github.com/go-kit/kit/tracing/opentracing"
	kithttp "github.com/go-kit/kit/transport/http"
	"github.com/go-zoo/bone"
	"github.com/mainflux/mainflux"
	internalhttp "github.com/mainflux/mainflux/internal/http"
	internalerr "github.com/mainflux/mainflux/internal/errors"
	"github.com/mainflux/mainflux/twins"
	opentracing "github.com/opentracing/opentracing-go"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	contentType = "application/json"

	offset   = "offset"
	limit    = "limit"
	name     = "name"
	metadata = "metadata"

	defLimit  = 10
	defOffset = 0
)

// MakeHandler returns a HTTP handler for API endpoints.
func MakeHandler(tracer opentracing.Tracer, svc twins.Service) http.Handler {
	opts := []kithttp.ServerOption{
		kithttp.ServerErrorEncoder(encodeError),
	}

	r := bone.New()

	r.Post("/twins", kithttp.NewServer(
		kitot.TraceServer(tracer, "add_twin")(addTwinEndpoint(svc)),
		decodeTwinCreation,
		encodeResponse,
		opts...,
	))

	r.Put("/twins/:id", kithttp.NewServer(
		kitot.TraceServer(tracer, "update_twin")(updateTwinEndpoint(svc)),
		decodeTwinUpdate,
		encodeResponse,
		opts...,
	))

	r.Get("/twins/:id", kithttp.NewServer(
		kitot.TraceServer(tracer, "view_twin")(viewTwinEndpoint(svc)),
		decodeView,
		encodeResponse,
		opts...,
	))

	r.Delete("/twins/:id", kithttp.NewServer(
		kitot.TraceServer(tracer, "remove_twin")(removeTwinEndpoint(svc)),
		decodeView,
		encodeResponse,
		opts...,
	))

	r.Get("/twins", kithttp.NewServer(
		kitot.TraceServer(tracer, "list_twins")(listTwinsEndpoint(svc)),
		decodeList,
		encodeResponse,
		opts...,
	))

	r.Get("/states/:id", kithttp.NewServer(
		kitot.TraceServer(tracer, "list_states")(listStatesEndpoint(svc)),
		decodeListStates,
		encodeResponse,
		opts...,
	))

	r.GetFunc("/version", mainflux.Version("twins"))
	r.Handle("/metrics", promhttp.Handler())

	return r
}

func decodeTwinCreation(_ context.Context, r *http.Request) (interface{}, error) {
	if !strings.Contains(r.Header.Get("Content-Type"), contentType) {
		return nil, internalerr.ErrUnsupportedContentType
	}

	req := addTwinReq{token: r.Header.Get("Authorization")}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, err
	}

	return req, nil
}

func decodeTwinUpdate(_ context.Context, r *http.Request) (interface{}, error) {
	if !strings.Contains(r.Header.Get("Content-Type"), contentType) {
		return nil, internalerr.ErrUnsupportedContentType
	}

	req := updateTwinReq{
		token: r.Header.Get("Authorization"),
		id:    bone.GetValue(r, "id"),
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, err
	}

	return req, nil
}

func decodeView(_ context.Context, r *http.Request) (interface{}, error) {
	req := viewTwinReq{
		token: r.Header.Get("Authorization"),
		id:    bone.GetValue(r, "id"),
	}

	return req, nil
}

func decodeList(_ context.Context, r *http.Request) (interface{}, error) {
	l, err := internalhttp.ReadUintQuery(r, limit, defLimit)
	if err != nil {
		return nil, err
	}

	o, err := internalhttp.ReadUintQuery(r, offset, defOffset)
	if err != nil {
		return nil, err
	}

	n, err := internalhttp.ReadStringQuery(r, name)
	if err != nil {
		return nil, err
	}

	m, err := internalhttp.ReadMetadataQuery(r, "metadata")
	if err != nil {
		return nil, err
	}

	req := listReq{
		token:    r.Header.Get("Authorization"),
		limit:    l,
		offset:   o,
		name:     n,
		metadata: m,
	}

	return req, nil
}

func decodeListStates(_ context.Context, r *http.Request) (interface{}, error) {
	l, err := internalhttp.ReadUintQuery(r, limit, defLimit)
	if err != nil {
		return nil, err
	}

	o, err := internalhttp.ReadUintQuery(r, offset, defOffset)
	if err != nil {
		return nil, err
	}

	req := listStatesReq{
		token:  r.Header.Get("Authorization"),
		limit:  l,
		offset: o,
		id:     bone.GetValue(r, "id"),
	}

	return req, nil
}

func encodeResponse(_ context.Context, w http.ResponseWriter, response interface{}) error {
	w.Header().Set("Content-Type", contentType)

	if ar, ok := response.(mainflux.Response); ok {
		for k, v := range ar.Headers() {
			w.Header().Set(k, v)
		}

		w.WriteHeader(ar.Code())

		if ar.Empty() {
			return nil
		}
	}

	return json.NewEncoder(w).Encode(response)
}

func encodeError(_ context.Context, err error, w http.ResponseWriter) {
	w.Header().Set("Content-Type", contentType)

	switch err {
	case twins.ErrMalformedEntity:
		w.WriteHeader(http.StatusBadRequest)
	case twins.ErrUnauthorizedAccess:
		w.WriteHeader(http.StatusForbidden)
	case twins.ErrNotFound:
		w.WriteHeader(http.StatusNotFound)
	case twins.ErrConflict:
		w.WriteHeader(http.StatusUnprocessableEntity)
	case internalerr.ErrUnsupportedContentType:
		w.WriteHeader(http.StatusUnsupportedMediaType)
	case internalerr.ErrInvalidQueryParams:
		w.WriteHeader(http.StatusBadRequest)
	case io.ErrUnexpectedEOF:
		w.WriteHeader(http.StatusBadRequest)
	case io.EOF:
		w.WriteHeader(http.StatusBadRequest)
	default:
		switch err.(type) {
		case *json.SyntaxError:
			w.WriteHeader(http.StatusBadRequest)
		case *json.UnmarshalTypeError:
			w.WriteHeader(http.StatusBadRequest)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}
}
