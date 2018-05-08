package grpc_test

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/mainflux/mainflux"
	"github.com/mainflux/mainflux/users"
	grpcapi "github.com/mainflux/mainflux/users/api/grpc"
	"github.com/mainflux/mainflux/users/mocks"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const tcpPort = 8080

var user = users.User{"john.doe@email.com", "pass"}

func newService() users.Service {
	repo := mocks.NewUserRepository()
	hasher := mocks.NewHasher()
	idp := mocks.NewIdentityProvider()

	return users.New(repo, hasher, idp)
}

func startGRPCServer(svc users.Service, port int) {
	listener, _ := net.Listen("tcp", fmt.Sprintf(":%d", port))
	server := grpc.NewServer()
	mainflux.RegisterUsersServiceServer(server, grpcapi.NewServer(svc))
	go server.Serve(listener)
}

func TestIdentify(t *testing.T) {
	svc := newService()
	startGRPCServer(svc, tcpPort)
	svc.Register(user)

	usersAddr := fmt.Sprintf("localhost:%d", tcpPort)
	conn, _ := grpc.Dial(usersAddr, grpc.WithInsecure())
	client := grpcapi.NewClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	cases := map[string]struct {
		token string
		id    string
		err   error
	}{
		"identify user with valid token":   {user.Email, user.Email, nil},
		"identify user that doesn't exist": {"", "", status.Error(codes.InvalidArgument, "received invalid token request")},
	}

	for desc, tc := range cases {
		id, err := client.Identify(ctx, &mainflux.Token{tc.token})
		assert.Equal(t, tc.id, id.GetValue(), fmt.Sprintf("%s: expected %s got %s", desc, tc.id, id.GetValue()))
		assert.Equal(t, tc.err, err, fmt.Sprintf("%s: expected %s got %s", desc, tc.err, err))
	}
}
