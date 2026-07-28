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

func TestServicePreparedUsersAtomicPublication(t *testing.T) {
	t.Parallel()
	service, handler := newServiceTest(t)
	const (
		oldUUID = "11111111-1111-4111-8111-111111111111"
		newUUID = "22222222-2222-4222-8222-222222222222"
	)

	oldUsers, err := service.PrepareUsers(
		[]string{"old-user"},
		[]string{oldUUID},
		[]string{""},
	)
	if err != nil {
		t.Fatalf("PrepareUsers(old) error = %v", err)
	}
	service.InstallUsers(oldUsers)

	newUsers, err := service.PrepareUsers(
		[]string{"new-user"},
		[]string{newUUID},
		[]string{""},
	)
	if err != nil {
		t.Fatalf("PrepareUsers(new) error = %v", err)
	}

	observation, err := authenticateService(service, handler, oldUUID, "")
	if err != nil {
		t.Fatalf("old user before install error = %v", err)
	}
	if !observation.loaded || observation.user != "old-user" {
		t.Fatalf("old user before install = %+v", observation)
	}
	if _, err = authenticateService(service, handler, newUUID, ""); err == nil {
		t.Fatal("prepared state became visible before InstallUsers")
	}

	service.InstallUsers(newUsers)
	if _, err = authenticateService(service, handler, oldUUID, ""); err == nil {
		t.Fatal("old state remained visible after InstallUsers")
	}
	observation, err = authenticateService(service, handler, newUUID, "")
	if err != nil {
		t.Fatalf("new user after install error = %v", err)
	}
	if !observation.loaded || observation.user != "new-user" {
		t.Fatalf("new user after install = %+v", observation)
	}

	_, err = service.PrepareUsers(
		[]string{"first", "second"},
		[]string{newUUID, newUUID},
		[]string{"", ""},
	)
	if err == nil {
		t.Fatal("PrepareUsers accepted duplicate UUID credentials")
	}
	if strings.Contains(err.Error(), newUUID) {
		t.Fatalf("duplicate UUID error leaked credential: %v", err)
	}
	observation, err = authenticateService(service, handler, newUUID, "")
	if err != nil {
		t.Fatalf("failed prepare changed published state: %v", err)
	}
	if observation.user != "new-user" {
		t.Fatalf("failed prepare published user = %q", observation.user)
	}
}

func TestServiceConcurrentAuthenticationAndPublication(t *testing.T) {
	t.Parallel()
	service, handler := newServiceTest(t)
	const sharedUUID = "33333333-3333-4333-8333-333333333333"

	plainUsers, err := service.PrepareUsers(
		[]string{"plain-user"},
		[]string{sharedUUID},
		[]string{""},
	)
	if err != nil {
		t.Fatalf("PrepareUsers(plain) error = %v", err)
	}
	_, err = service.PrepareUsers(
		[]string{"vision-user"},
		[]string{sharedUUID},
		[]string{FlowVision},
	)
	if err != nil {
		t.Fatalf("PrepareUsers(vision) error = %v", err)
	}
	service.InstallUsers(plainUsers)

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
