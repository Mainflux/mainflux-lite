package mocks

import (
	"fmt"
	"strings"
	"sync"

	"github.com/mainflux/mainflux/manager"
)

var _ manager.ClientRepository = (*clientRepositoryMock)(nil)

const cliID = "123e4567-e89b-12d3-a456-"

type clientRepositoryMock struct {
	mu      sync.Mutex
	counter int
	clients map[string]manager.Client
}

// NewClientRepository creates in-memory client repository.
func NewClientRepository() manager.ClientRepository {
	return &clientRepositoryMock{
		clients: make(map[string]manager.Client),
	}
}

func (crm *clientRepositoryMock) ID() string {
	crm.mu.Lock()
	defer crm.mu.Unlock()

	crm.counter++
	return fmt.Sprintf("%s%012d", cliID, crm.counter)
}

func (crm *clientRepositoryMock) Save(client manager.Client) error {
	crm.mu.Lock()
	defer crm.mu.Unlock()

	crm.clients[key(client.Owner, client.ID)] = client

	return nil
}

func (crm *clientRepositoryMock) Update(client manager.Client) error {
	crm.mu.Lock()
	defer crm.mu.Unlock()

	dbKey := key(client.Owner, client.ID)

	if _, ok := crm.clients[dbKey]; !ok {
		return manager.ErrNotFound
	}

	crm.clients[dbKey] = client

	return nil
}

func (crm *clientRepositoryMock) One(owner, id string) (manager.Client, error) {
	if c, ok := crm.clients[key(owner, id)]; ok {
		return c, nil
	}

	return manager.Client{}, manager.ErrNotFound
}

func (crm *clientRepositoryMock) All(owner string, offset, limit int) []manager.Client {
	// This obscure way to examine map keys is enforced by the key structure
	// itself (see mocks/commons.go).
	prefix := fmt.Sprintf("%s-", owner)
	clients := make([]manager.Client, 0)

	if offset < 0 || limit <= 0 {
		return clients
	}

	// Since IDs start from 1, shift everything by one.
	first := fmt.Sprintf("%s%012d", cliID, offset+1)
	last := fmt.Sprintf("%s%012d", cliID, offset+limit+1)

	for k, v := range crm.clients {
		if strings.HasPrefix(k, prefix) && v.ID >= first && v.ID < last {
			clients = append(clients, v)
		}
	}

	return clients
}

func (crm *clientRepositoryMock) Remove(owner, id string) error {
	delete(crm.clients, key(owner, id))
	return nil
}
