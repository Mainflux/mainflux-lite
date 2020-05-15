// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package mocks

import (
	"fmt"
	"sync"

	"github.com/mainflux/mainflux"
)

// Prefix represents the prefix used to generate UUID mocks
const Prefix = "123e4567-e89b-12d3-a456-"

var _ mainflux.UUIDProvider = (*uuidProviderMock)(nil)

type uuidProviderMock struct {
	mu      sync.Mutex
	counter int
}

func (up *uuidProviderMock) ID() (string, error) {
	up.mu.Lock()
	defer up.mu.Unlock()

	up.counter++
	return fmt.Sprintf("%s%012d", Prefix, up.counter), nil
}

// New creates "mirror" uuid provider, i.e. generated
// token will hold value provided by the caller.
func New() mainflux.UUIDProvider {
	return &uuidProviderMock{}
}