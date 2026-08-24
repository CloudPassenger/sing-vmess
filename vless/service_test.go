package vless

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	vmess "github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const serviceTestTimeout = 3 * time.Second

type serviceAuthObservation struct {
	user   string
	loaded bool
}

type serviceTestHandler struct {
	observations chan serviceAuthObservation
}

func (h *serviceTestHandler) NewConnectionEx(
	ctx context.Context,
	conn net.Conn,
	source M.Socksaddr,
	destination M.Socksaddr,
	onClose N.CloseHandlerFunc,
) {
	user, loaded := auth.UserFromContext[string](ctx)
	h.observations <- serviceAuthObservation{
		user:   user,
		loaded: loaded,
	}
	_ = conn.Close()
	if onClose != nil {
		onClose(nil)
	}
}

func (h *serviceTestHandler) NewPacketConnectionEx(
	ctx context.Context,
	conn N.PacketConn,
	source M.Socksaddr,
	destination M.Socksaddr,
	onClose N.CloseHandlerFunc,
) {
	_ = conn.Close()
	if onClose != nil {
		onClose(nil)
	}
}

func newServiceTest(t *testing.T) (*Service[string], *serviceTestHandler) {
	t.Helper()
	handler := &serviceTestHandler{
		observations: make(chan serviceAuthObservation, 1024),
	}
	service, err := NewService[string](context.Background(), "", logger.NOP(), handler)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	return service, handler
}

func authenticateService(
	service *Service[string],
	handler *serviceTestHandler,
	userUUID string,
	flow string,
) (serviceAuthObservation, error) {
	serverConn, clientConn := net.Pipe()
	errCh := make(chan error, 1)
	go func() {
		defer serverConn.Close()
		errCh <- service.NewConnection(context.Background(), serverConn, M.Socksaddr{}, nil)
	}()

	request := Request{
		UUID:        normalizeUserUUID(userUUID),
		Command:     vmess.CommandTCP,
		Destination: M.Socksaddr{Fqdn: "example.com", Port: 443},
		Flow:        flow,
	}
	if err := WriteRequest(clientConn, request, nil); err != nil {
		_ = clientConn.Close()
		return serviceAuthObservation{}, err
	}

	var err error
	select {
	case err = <-errCh:
	case <-time.After(serviceTestTimeout):
		_ = clientConn.Close()
		return serviceAuthObservation{}, fmt.Errorf("timed out waiting for VLESS authentication")
	}
	_ = clientConn.Close()
	if err != nil {
		return serviceAuthObservation{}, err
	}

	select {
	case observation := <-handler.observations:
		return observation, nil
	case <-time.After(serviceTestTimeout):
		return serviceAuthObservation{}, fmt.Errorf("timed out waiting for VLESS auth identity")
	}
}

func TestServiceUpdateUsersAtomicPublication(t *testing.T) {
	t.Parallel()
	service, handler := newServiceTest(t)
	const (
		oldUUID = "11111111-1111-4111-8111-111111111111"
		newUUID = "22222222-2222-4222-8222-222222222222"
	)

	service.UpdateUsers([]string{"old-user"}, []string{oldUUID}, []string{""})

	observation, err := authenticateService(service, handler, oldUUID, "")
	if err != nil {
		t.Fatalf("old user error = %v", err)
	}
	if !observation.loaded || observation.user != "old-user" {
		t.Fatalf("old user = %+v", observation)
	}
	if _, err = authenticateService(service, handler, newUUID, ""); err == nil {
		t.Fatal("unpublished credential authenticated")
	}

	service.UpdateUsers([]string{"new-user"}, []string{newUUID}, []string{""})
	if _, err = authenticateService(service, handler, oldUUID, ""); err == nil {
		t.Fatal("replaced credential still authenticates")
	}
	observation, err = authenticateService(service, handler, newUUID, "")
	if err != nil {
		t.Fatalf("new user error = %v", err)
	}
	if !observation.loaded || observation.user != "new-user" {
		t.Fatalf("new user = %+v", observation)
	}

	// Mismatched list lengths leave the published state untouched.
	service.UpdateUsers([]string{"first", "second"}, []string{newUUID}, []string{""})
	observation, err = authenticateService(service, handler, newUUID, "")
	if err != nil {
		t.Fatalf("rejected update changed published state: %v", err)
	}
	if observation.user != "new-user" {
		t.Fatalf("rejected update published user = %q", observation.user)
	}
}

func TestServiceConcurrentAuthenticationAndPublication(t *testing.T) {
	t.Parallel()
	service, handler := newServiceTest(t)
	const sharedUUID = "33333333-3333-4333-8333-333333333333"

	service.UpdateUsers([]string{"plain-user"}, []string{sharedUUID}, []string{""})

	stop := make(chan struct{})
	var updateGroup sync.WaitGroup
	updateGroup.Add(1)
	go func() {
		defer updateGroup.Done()
		for {
			select {
			case <-stop:
				return
			default:
				service.UpdateUsers([]string{"plain-user"}, []string{sharedUUID}, []string{""})
				time.Sleep(25 * time.Microsecond)
				service.UpdateUsers([]string{"vision-user"}, []string{sharedUUID}, []string{FlowVision})
				time.Sleep(25 * time.Microsecond)
			}
		}
	}()

	for range 500 {
		observation, authErr := authenticateService(service, handler, sharedUUID, "")
		if authErr != nil {
			if !strings.Contains(authErr.Error(), "flow mismatch") {
				close(stop)
				updateGroup.Wait()
				t.Fatalf("authentication error = %v", authErr)
			}
			continue
		}
		if !observation.loaded || observation.user != "plain-user" {
			close(stop)
			updateGroup.Wait()
			t.Fatalf("mixed identity/flow generation observed: %+v", observation)
		}
	}
	close(stop)
	updateGroup.Wait()
}
