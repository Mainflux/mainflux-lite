//
// Copyright (c) 2019
// Mainflux
//
// SPDX-License-Identifier: Apache-2.0
//

// +build !test

package api

import (
	"time"

	"github.com/go-kit/kit/metrics"
	"github.com/mainflux/mainflux/twins"
)

var _ twins.Service = (*metricsMiddleware)(nil)

type metricsMiddleware struct {
	counter metrics.Counter
	latency metrics.Histogram
	svc     twins.Service
}

// MetricsMiddleware instruments core service by tracking request count and
// latency.
func MetricsMiddleware(svc twins.Service, counter metrics.Counter, latency metrics.Histogram) twins.Service {
	return &metricsMiddleware{
		counter: counter,
		latency: latency,
		svc:     svc,
	}
}

func (ms *metricsMiddleware) Ping(secret string) (response string, err error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "ping").Add(1)
		ms.latency.With("method", "ping").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return ms.svc.Ping(secret)
}