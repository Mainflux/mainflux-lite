// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	kithttp "github.com/go-kit/kit/transport/http"
	"github.com/go-zoo/bone"
	"github.com/mainflux/mainflux"
	"github.com/mainflux/mainflux/internal/httputil"
	"github.com/mainflux/mainflux/pkg/errors"
	"github.com/mainflux/mainflux/readers"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	contentType = "application/json"
	defLimit    = 10
	defOffset   = 0
	format      = "format"
	defFormat   = "messages"
)

var (
	errUnauthorizedAccess = errors.New("missing or invalid credentials provided")
	auth                  mainflux.ThingsServiceClient
)

// MakeHandler returns a HTTP handler for API endpoints.
func MakeHandler(svc readers.MessageRepository, tc mainflux.ThingsServiceClient, svcName string) http.Handler {
	auth = tc

	opts := []kithttp.ServerOption{
		kithttp.ServerErrorEncoder(encodeError),
	}

	mux := bone.New()
	mux.Get("/channels/:chanID/messages", kithttp.NewServer(
		listMessagesEndpoint(svc),
		decodeList,
		encodeResponse,
		opts...,
	))

	mux.GetFunc("/version", mainflux.Version(svcName))
	mux.Handle("/metrics", promhttp.Handler())

	return mux
}

func decodeList(_ context.Context, r *http.Request) (interface{}, error) {
	chanID := bone.GetValue(r, "chanID")
	if chanID == "" {
		return nil, errors.ErrInvalidQueryParams
	}

	if err := authorize(r, chanID); err != nil {
		return nil, err
	}

	offset, err := httputil.ReadUintQuery(r, "offset", defOffset)
	if err != nil {
		return nil, err
	}

	limit, err := httputil.ReadUintQuery(r, "limit", defLimit)
	if err != nil {
		return nil, err
	}

	format, err := httputil.ReadStringQuery(r, "format")
	if err != nil {
		return nil, err
	}
	if format != "" {
		format = defFormat
	}

	subtopic, err := httputil.ReadStringQuery(r, "subtopic")
	if err != nil {
		return nil, err
	}

	publisher, err := httputil.ReadStringQuery(r, "publisher")
	if err != nil {
		return nil, err
	}

	protocol, err := httputil.ReadStringQuery(r, "protocol")
	if err != nil {
		return nil, err
	}

	name, err := httputil.ReadStringQuery(r, "name")
	if err != nil {
		return nil, err
	}

	v, err := httputil.ReadFloatQuery(r, "v")
	if err != nil {
		return nil, err
	}

	comparator, err := httputil.ReadStringQuery(r, "comparator")
	if err != nil {
		return nil, err
	}

	vs, err := httputil.ReadStringQuery(r, "vs")
	if err != nil {
		return nil, err
	}

	vd, err := httputil.ReadStringQuery(r, "vd")
	if err != nil {
		return nil, err
	}

	from, err := httputil.ReadFloatQuery(r, "from")
	if err != nil {
		return nil, err
	}

	to, err := httputil.ReadFloatQuery(r, "to")
	if err != nil {
		return nil, err
	}

	req := listMessagesReq{
		chanID: chanID,
		pageMeta: readers.PageMetadata{
			Offset:      offset,
			Limit:       limit,
			Format:      format,
			Subtopic:    subtopic,
			Publisher:   publisher,
			Protocol:    protocol,
			Name:        name,
			Value:       v,
			Comparator:  comparator,
			StringValue: vs,
			DataValue:   vd,
			From:        from,
			To:          to,
		},
	}

	vb, err := readBoolValueQuery(r, "vb")
	if err != nil {
		return nil, err
	}
	if vb != nil {
		req.pageMeta.BoolValue = *vb
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
	switch {
	case errors.Contains(err, nil):
	case errors.Contains(err, errors.ErrInvalidQueryParams):
		w.WriteHeader(http.StatusBadRequest)
	case errors.Contains(err, errUnauthorizedAccess):
		w.WriteHeader(http.StatusForbidden)
	default:
		w.WriteHeader(http.StatusInternalServerError)
	}
	errorVal, ok := err.(errors.Error)
	if ok {
		w.Header().Set("Content-Type", contentType)
		if err := json.NewEncoder(w).Encode(errorRes{Err: errorVal.Msg()}); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}
	}
}

func authorize(r *http.Request, chanID string) error {
	token := r.Header.Get("Authorization")
	if token == "" {
		return errUnauthorizedAccess
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_, err := auth.CanAccessByKey(ctx, &mainflux.AccessByKeyReq{Token: token, ChanID: chanID})
	if err != nil {
		e, ok := status.FromError(err)
		if ok && e.Code() == codes.PermissionDenied {
			return errUnauthorizedAccess
		}
		return err
	}

	return nil
}

func readBoolValueQuery(r *http.Request, key string) (*bool, error) {
	vals := bone.GetQuery(r, key)
	if len(vals) > 1 {
		return nil, errors.ErrInvalidQueryParams
	}

	if len(vals) == 0 {
		return nil, nil
	}

	b, err := strconv.ParseBool(vals[0])
	if err != nil {
		return nil, errors.ErrInvalidQueryParams
	}

	return &b, nil
}
