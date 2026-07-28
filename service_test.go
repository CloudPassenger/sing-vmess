package vmess

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing/common/auth"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const serviceHandshakeTimeout = 3 * time.Second

const (
	serviceUUIDOld     = "10000000-0000-4000-8000-000000000001"
	serviceUUIDNew     = "10000000-0000-4000-8000-000000000002"
	serviceUUIDSwapOne = "10000000-0000-4000-8000-000000000003"
	serviceUUIDSwapTwo = "10000000-0000-4000-8000-000000000004"
)

type serviceTestHandler struct {
	identities chan string
	failures   chan error
}

func (h *serviceTestHandler) NewConnectionEx(
	ctx context.Context,
	conn net.Conn,
	source M.Socksaddr,
	destination M.Socksaddr,
	onClose N.CloseHandlerFunc,
) {
	user, loaded := auth.UserFromContext[string](ctx)
	if !loaded {
		h.failures <- fmt.Errorf("VMess service handler received no user identity")
		_ = conn.Close()
		return
	}
	if !serviceDestinationAllowsUser(destination.Fqdn, user) {
		h.failures <- fmt.Errorf(
			"destination %q was attributed to VMess service user %q",
			destination.Fqdn,
			user,
		)
	}
	h.identities <- user
	defer func() {
		_ = conn.Close()
		if onClose != nil {
			onClose(nil)
		}
	}()

	buffer := make([]byte, 1024)
	for {
		n, err := conn.Read(buffer)
		if n > 0 {
			if _, writeErr := conn.Write(buffer[:n]); writeErr != nil {
				return
			}
		}
		if err != nil {
			return
		}
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

func serviceDestinationAllowsUser(destination string, user string) bool {
	if destination == "swap.service.test" {
		return user == "alice" || user == "bob"
	}
	expected, _, loaded := strings.Cut(destination, ".")
	return loaded && expected == user
}

type serviceTestHarness struct {
	ctx               context.Context
	cancel            context.CancelFunc
	service           *Service[string]
	handler           *serviceTestHandler
	listener          net.Listener
	acceptDone        chan struct{}
	connectionGroup   sync.WaitGroup
	connectionsAccess sync.Mutex
	connections       []net.Conn
	closeOnce         sync.Once
}

func newServiceTestHarness(
	t *testing.T,
	users []string,
	userIDs []string,
	alterIDs []int,
) *serviceTestHarness {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	handler := &serviceTestHandler{
		identities: make(chan string, 2048),
		failures:   make(chan error, 2048),
	}
	service := NewService[string](handler)
	if err := service.UpdateUsers(users, userIDs, alterIDs); err != nil {
		cancel()
		t.Fatal(err)
	}
	if err := service.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		cancel()
		_ = service.Close()
		t.Fatal(err)
	}

	harness := &serviceTestHarness{
		ctx:         ctx,
		cancel:      cancel,
		service:     service,
		handler:     handler,
		listener:    listener,
		acceptDone:  make(chan struct{}),
		connections: make([]net.Conn, 0),
	}
	go harness.acceptConnections()
	t.Cleanup(harness.close)
	return harness
}

func (h *serviceTestHarness) acceptConnections() {
	defer close(h.acceptDone)
	for {
		conn, err := h.listener.Accept()
		if err != nil {
			return
		}
		h.connectionGroup.Add(1)
		go func() {
			defer h.connectionGroup.Done()
			defer conn.Close()
			_ = h.service.NewConnection(h.ctx, conn, M.Socksaddr{}, nil)
		}()
	}
}

func (h *serviceTestHarness) open(
	userUUID string,
	alterID int,
	expectedUser string,
	payload string,
) (net.Conn, error) {
	client, err := NewClient(userUUID, "none", alterID)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(h.ctx, serviceHandshakeTimeout)
	defer cancel()
	var dialer net.Dialer
	upstream, err := dialer.DialContext(ctx, "tcp", h.listener.Addr().String())
	if err != nil {
		return nil, err
	}
	conn, err := client.DialConn(upstream, M.Socksaddr{
		Fqdn: expectedUser + ".service.test",
		Port: 443,
	})
	if err != nil {
		_ = upstream.Close()
		return nil, err
	}
	if err := echoServiceConnection(conn, payload); err != nil {
		_ = conn.Close()
		return nil, err
	}

	h.connectionsAccess.Lock()
	h.connections = append(h.connections, conn)
	h.connectionsAccess.Unlock()
	return conn, nil
}

func (h *serviceTestHarness) openSwap(userUUID string, payload string) (net.Conn, error) {
	client, err := NewClient(userUUID, "none", 0)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(h.ctx, serviceHandshakeTimeout)
	defer cancel()
	var dialer net.Dialer
	upstream, err := dialer.DialContext(ctx, "tcp", h.listener.Addr().String())
	if err != nil {
		return nil, err
	}
	conn, err := client.DialConn(upstream, M.Socksaddr{
		Fqdn: "swap.service.test",
		Port: 443,
	})
	if err != nil {
		_ = upstream.Close()
		return nil, err
	}
	if err := echoServiceConnection(conn, payload); err != nil {
		_ = conn.Close()
		return nil, err
	}

	h.connectionsAccess.Lock()
	h.connections = append(h.connections, conn)
	h.connectionsAccess.Unlock()
	return conn, nil
}

func (h *serviceTestHarness) requireUser(t *testing.T, expected string) {
	t.Helper()
	select {
	case user := <-h.handler.identities:
		if user != expected {
			t.Fatalf("VMess service user = %q, want %q", user, expected)
		}
	case err := <-h.handler.failures:
		t.Fatal(err)
	case <-time.After(serviceHandshakeTimeout):
		t.Fatal("timed out waiting for VMess service identity")
	}
}

func (h *serviceTestHarness) requireRejected(
	t *testing.T,
	userUUID string,
	alterID int,
	expectedUser string,
) {
	t.Helper()
	conn, err := h.open(userUUID, alterID, expectedUser, "must-be-rejected")
	if err == nil {
		_ = conn.Close()
		t.Fatal("VMess service credential remained accepted")
	}
}

func (h *serviceTestHarness) requireNoFailures(t *testing.T) {
	t.Helper()
	for {
		select {
		case err := <-h.handler.failures:
			t.Fatal(err)
		default:
			return
		}
	}
}

func (h *serviceTestHarness) close() {
	h.closeOnce.Do(func() {
		h.connectionsAccess.Lock()
		connections := append([]net.Conn(nil), h.connections...)
		h.connections = nil
		h.connectionsAccess.Unlock()
		for _, conn := range connections {
			_ = conn.Close()
		}

		h.cancel()
		_ = h.listener.Close()
		<-h.acceptDone
		_ = h.service.Close()

		done := make(chan struct{})
		go func() {
			h.connectionGroup.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(serviceHandshakeTimeout):
		}
	})
}

func echoServiceConnection(conn net.Conn, payload string) error {
	if err := conn.SetDeadline(time.Now().Add(serviceHandshakeTimeout)); err != nil {
		return err
	}
	if _, err := conn.Write([]byte(payload)); err != nil {
		return err
	}
	received := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, received); err != nil {
		return err
	}
	if string(received) != payload {
		return fmt.Errorf("echo response %q does not match payload %q", received, payload)
	}
	return conn.SetDeadline(time.Time{})
}

func TestServicePreparedUsersPublishAtomically(t *testing.T) {
	t.Parallel()

	harness := newServiceTestHarness(
		t,
		[]string{"alice"},
		[]string{serviceUUIDOld},
		[]int{0},
	)
	prepared, err := harness.service.PrepareUsers(
		[]string{"alice"},
		[]string{serviceUUIDNew},
		[]int{0},
	)
	if err != nil {
		t.Fatal(err)
	}

	oldConn, err := harness.open(serviceUUIDOld, 0, "alice", "old-before-install")
	if err != nil {
		t.Fatal(err)
	}
	harness.requireUser(t, "alice")
	_ = oldConn.Close()
	harness.requireRejected(t, serviceUUIDNew, 0, "alice")

	harness.service.InstallUsers(prepared)
	harness.requireRejected(t, serviceUUIDOld, 0, "alice")
	newConn, err := harness.open(serviceUUIDNew, 0, "alice", "new-after-install")
	if err != nil {
		t.Fatal(err)
	}
	harness.requireUser(t, "alice")
	_ = newConn.Close()
	harness.requireNoFailures(t)
}

func TestServicePrepareUsersValidation(t *testing.T) {
	t.Parallel()

	service := NewService[string](nil)
	if _, err := service.PrepareUsers([]string{"alice"}, nil, []int{0}); err == nil {
		t.Fatal("PrepareUsers accepted mismatched user lists")
	}
	if _, err := service.PrepareUsers(
		[]string{"alice", "bob"},
		[]string{serviceUUIDOld, serviceUUIDOld},
		[]int{0, 0},
	); err == nil {
		t.Fatal("PrepareUsers accepted duplicate UUID credentials")
	} else if strings.Contains(err.Error(), serviceUUIDOld) {
		t.Fatalf("duplicate error leaked UUID credential: %v", err)
	}
	if _, err := service.PrepareUsers(
		[]string{"alice"},
		[]string{serviceUUIDOld},
		[]int{-1},
	); err == nil {
		t.Fatal("PrepareUsers accepted a negative alter ID")
	} else if strings.Contains(err.Error(), serviceUUIDOld) {
		t.Fatalf("alter ID error leaked UUID credential: %v", err)
	}
}

func TestServiceConcurrentPublicationUsesOneState(t *testing.T) {
	t.Parallel()

	harness := newServiceTestHarness(
		t,
		[]string{"alice", "bob"},
		[]string{serviceUUIDSwapOne, serviceUUIDSwapTwo},
		[]int{0, 0},
	)
	stateA, err := harness.service.PrepareUsers(
		[]string{"alice", "bob"},
		[]string{serviceUUIDSwapOne, serviceUUIDSwapTwo},
		[]int{0, 0},
	)
	if err != nil {
		t.Fatal(err)
	}
	stateB, err := harness.service.PrepareUsers(
		[]string{"bob", "alice"},
		[]string{serviceUUIDSwapOne, serviceUUIDSwapTwo},
		[]int{0, 0},
	)
	if err != nil {
		t.Fatal(err)
	}

	const workerCount = 6
	const attemptsPerWorker = 32
	start := make(chan struct{})
	workerErrors := make(chan error, workerCount*attemptsPerWorker)
	var successCount atomic.Int64
	var workers sync.WaitGroup
	workers.Add(workerCount)
	for workerIndex := range workerCount {
		go func() {
			defer workers.Done()
			<-start
			for attempt := range attemptsPerWorker {
				userUUID := serviceUUIDSwapOne
				if (workerIndex+attempt)%2 == 1 {
					userUUID = serviceUUIDSwapTwo
				}
				conn, err := harness.openSwap(
					userUUID,
					fmt.Sprintf("worker-%d-attempt-%d", workerIndex, attempt),
				)
				if err != nil {
					workerErrors <- err
					continue
				}
				successCount.Add(1)
				_ = conn.Close()
			}
		}()
	}

	close(start)
	for updateIndex := range 64 {
		if updateIndex%2 == 0 {
			harness.service.InstallUsers(stateB)
		} else {
			harness.service.InstallUsers(stateA)
		}
		time.Sleep(time.Millisecond)
	}
	workers.Wait()
	close(workerErrors)
	for err := range workerErrors {
		t.Errorf("VMess service handshake observed mixed state: %v", err)
	}
	if successCount.Load() != int64(workerCount*attemptsPerWorker) {
		t.Fatalf(
			"successful VMess service handshakes = %d, want %d",
			successCount.Load(),
			workerCount*attemptsPerWorker,
		)
	}
	harness.requireNoFailures(t)
}

func TestServiceAlterIDRefreshLifecycleAndStaleCAS(t *testing.T) {
	t.Parallel()

	service := NewService[string](nil)
	t.Cleanup(func() {
		_ = service.Close()
	})
	service.refreshInterval = 5 * time.Millisecond
	if err := service.UpdateUsers([]string{}, []string{}, []int{}); err != nil {
		t.Fatal(err)
	}
	if err := service.Start(); err != nil {
		t.Fatal(err)
	}
	if err := service.Start(); err != nil {
		t.Fatal(err)
	}

	withAlterID, err := service.PrepareUsers(
		[]string{"legacy"},
		[]string{serviceUUIDOld},
		[]int{1},
	)
	if err != nil {
		t.Fatal(err)
	}
	service.InstallUsers(withAlterID)
	installedAlterState := withAlterID.state
	deadline := time.Now().Add(time.Second)
	for service.state.Load() == installedAlterState && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	refreshedAlterState := service.state.Load()
	if refreshedAlterState == installedAlterState {
		t.Fatal("alter-ID refresh did not activate after runtime installation")
	}
	if !refreshedAlterState.hasAlterIDs {
		t.Fatal("alter-ID refresh dropped alter-ID source data")
	}

	withoutAlterID, err := service.PrepareUsers(
		[]string{"modern"},
		[]string{serviceUUIDNew},
		[]int{0},
	)
	if err != nil {
		t.Fatal(err)
	}
	service.InstallUsers(withoutAlterID)
	installedModernState := withoutAlterID.state
	if service.refreshLegacyKeysFrom(refreshedAlterState, time.Now().Unix()+1) {
		t.Fatal("stale alter-ID refresh overwrote a newer user state")
	}
	if service.state.Load() != installedModernState {
		t.Fatal("stale alter-ID refresh changed the installed user state")
	}
	time.Sleep(4 * service.refreshInterval)
	if service.state.Load() != installedModernState {
		t.Fatal("alter-ID refresh did not idle after the last alter-ID user was removed")
	}

	const closerCount = 8
	closeErrors := make(chan error, closerCount)
	var closers sync.WaitGroup
	closers.Add(closerCount)
	for range closerCount {
		go func() {
			defer closers.Done()
			closeErrors <- service.Close()
		}()
	}
	closers.Wait()
	close(closeErrors)
	for err := range closeErrors {
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := service.Start(); err != nil {
		t.Fatal(err)
	}
}
