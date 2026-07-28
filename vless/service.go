package vless

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync/atomic"

	"github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing-vmess/vless/encryption"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/gofrs/uuid/v5"
)

type userEntry[T comparable] struct {
	user T
	flow string
}

type userState[T comparable] struct {
	userMap map[[16]byte]userEntry[T]
}

type PreparedUsers[T comparable] struct {
	state *userState[T]
}

type Service[T comparable] struct {
	users   atomic.Pointer[userState[T]]
	logger  logger.Logger
	handler Handler

	decryption *encryption.Service
}

type Handler interface {
	N.TCPConnectionHandlerEx
	N.UDPConnectionHandlerEx
}

func NewService[T comparable](ctx context.Context, decryptionOptions string, logger logger.Logger, handler Handler) (*Service[T], error) {
	var decryption *encryption.Service
	switch decryptionOptions {
	case "", "none":
	default:
		xorMode, secondsFrom, secondsTo, nfsKeyBytes, paddings, err := encryption.ParseDecryption(decryptionOptions)
		if err != nil {
			return nil, E.Cause(err, "parse decryption")
		}
		decryption, err = encryption.NewService(ctx, nfsKeyBytes, xorMode, secondsFrom, secondsTo, paddings)
		if err != nil {
			return nil, E.Cause(err, "create decryption")
		}
	}
	service := &Service[T]{
		logger:  logger,
		handler: handler,

		decryption: decryption,
	}
	service.users.Store(&userState[T]{
		userMap: make(map[[16]byte]userEntry[T]),
	})
	return service, nil
}

func (s *Service[T]) Start() error {
	if s.decryption != nil {
		_ = s.decryption.Start()
		var aeadType string
		if encryption.HasAESGCMHardwareSupport {
			aeadType = "aes"
		} else {
			aeadType = "chacha20"
		}
		s.logger.Info("decryption server started with default AEAD: ", aeadType)
	}
	return nil
}

func (s *Service[T]) Close() error {
	if s == nil || s.decryption == nil {
		return nil
	}
	return common.Close(s.decryption)
}

func (s *Service[T]) PrepareUsers(userList []T, userUUIDList []string, userFlowList []string) (*PreparedUsers[T], error) {
	if len(userList) != len(userUUIDList) || len(userList) != len(userFlowList) {
		return nil, E.New("mismatched VLESS user list lengths")
	}
	userMap := make(map[[16]byte]userEntry[T], len(userList))
	for index, user := range userList {
		userFlow := userFlowList[index]
		switch userFlow {
		case "", FlowVision:
		default:
			return nil, E.New("unsupported VLESS flow at user index ", index)
		}
		userUUID := normalizeUserUUID(userUUIDList[index])
		if _, loaded := userMap[userUUID]; loaded {
			return nil, E.New("duplicate VLESS UUID credential at user index ", index)
		}
		userMap[userUUID] = userEntry[T]{
			user: user,
			flow: userFlow,
		}
	}
	return &PreparedUsers[T]{
		state: &userState[T]{
			userMap: userMap,
		},
	}, nil
}

func (s *Service[T]) InstallUsers(users *PreparedUsers[T]) {
	s.users.Store(users.state)
}

func (s *Service[T]) UpdateUsers(userList []T, userUUIDList []string, userFlowList []string) {
	users, err := s.PrepareUsers(userList, userUUIDList, userFlowList)
	if err != nil {
		return
	}
	s.InstallUsers(users)
}

func (s *Service[T]) NewConnection(ctx context.Context, conn net.Conn, source M.Socksaddr, onClose N.CloseHandlerFunc) error {
	originConn := conn
	if s.decryption != nil {
		var err error
		conn, err = s.decryption.Handshake(conn, nil)
		if err != nil {
			return E.Cause(err, "decryption handshake")
		}
	}
	request, err := ReadRequest(conn)
	if err != nil {
		return err
	}
	state := s.users.Load()
	entry, loaded := state.userMap[request.UUID]
	if !loaded {
		return E.New("unknown UUID")
	}
	ctx = auth.ContextWithUser(ctx, entry.user)
	userFlow := entry.flow
	if request.Flow == FlowVision && request.Command == vmess.NetworkUDP {
		return E.New(FlowVision, " flow does not support UDP")
	} else if request.Flow != userFlow {
		return E.New("flow mismatch: expected ", flowName(userFlow), ", but got ", flowName(request.Flow))
	}

	if request.Command == vmess.CommandUDP {
		s.handler.NewPacketConnectionEx(ctx, &serverPacketConn{ExtendedConn: bufio.NewExtendedConn(conn), destination: request.Destination}, source, request.Destination, onClose)
		return nil
	}
	responseConn := &serverConn{ExtendedConn: bufio.NewExtendedConn(conn)}
	switch userFlow {
	case FlowVision:
		conn, err = NewVisionConn(responseConn, originConn, request.UUID, s.logger)
		if err != nil {
			return E.Cause(err, "initialize vision")
		}
	case "":
		conn = responseConn
	default:
		return E.New("unknown flow: ", userFlow)
	}
	switch request.Command {
	case vmess.CommandTCP:
		s.handler.NewConnectionEx(ctx, conn, source, request.Destination, onClose)
		return nil
	case vmess.CommandMux:
		return vmess.HandleMuxConnection(ctx, conn, source, s.handler)
	default:
		return E.New("unknown command: ", request.Command)
	}
}

func flowName(value string) string {
	if value == "" {
		return "none"
	}
	return value
}

func normalizeUserUUID(value string) [16]byte {
	userID, err := uuid.FromString(value)
	if err != nil {
		userID = uuid.NewV5(uuid.Nil, value)
	}
	return userID
}

type serverConn struct {
	N.ExtendedConn
	responseWritten bool
}

func (c *serverConn) Read(b []byte) (n int, err error) {
	return c.ExtendedConn.Read(b)
}

func (c *serverConn) Write(b []byte) (n int, err error) {
	if !c.responseWritten {
		buffer := buf.NewSize(2 + len(b))
		buffer.WriteByte(Version)
		buffer.WriteByte(0)
		buffer.Write(b)
		_, err = c.ExtendedConn.Write(buffer.Bytes())
		buffer.Release()
		if err == nil {
			n = len(b)
		}
		c.responseWritten = true
		return
	}
	return c.ExtendedConn.Write(b)
}

func (c *serverConn) WriteBuffer(buffer *buf.Buffer) error {
	if !c.responseWritten {
		header := buffer.ExtendHeader(2)
		header[0] = Version
		header[1] = 0
		c.responseWritten = true
	}
	return c.ExtendedConn.WriteBuffer(buffer)
}

func (c *serverConn) FrontHeadroom() int {
	if c.responseWritten {
		return 0
	}
	return 2
}

func (c *serverConn) ReaderReplaceable() bool {
	return true
}

func (c *serverConn) WriterReplaceable() bool {
	return c.responseWritten
}

func (c *serverConn) NeedAdditionalReadDeadline() bool {
	return true
}

func (c *serverConn) Upstream() any {
	return c.ExtendedConn
}

type serverPacketConn struct {
	N.ExtendedConn
	responseWritten bool
	destination     M.Socksaddr
}

func (c *serverPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	var packetLen uint16
	err = binary.Read(c.ExtendedConn, binary.BigEndian, &packetLen)
	if err != nil {
		return
	}
	if len(p) < int(packetLen) {
		err = io.ErrShortBuffer
		return
	}
	n, err = io.ReadFull(c.ExtendedConn, p[:packetLen])
	if err != nil {
		return
	}
	if c.destination.IsFqdn() {
		addr = c.destination
	} else {
		addr = c.destination.UDPAddr()
	}
	return
}

func (c *serverPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if !c.responseWritten {
		_, err = c.ExtendedConn.Write([]byte{Version, 0})
		if err != nil {
			return
		}
		c.responseWritten = true
	}
	err = binary.Write(c.ExtendedConn, binary.BigEndian, uint16(len(p)))
	if err != nil {
		return
	}
	return c.ExtendedConn.Write(p)
}

func (c *serverPacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	var packetLen uint16
	err = binary.Read(c.ExtendedConn, binary.BigEndian, &packetLen)
	if err != nil {
		return
	}

	_, err = buffer.ReadFullFrom(c.ExtendedConn, int(packetLen))
	if err != nil {
		return
	}

	destination = c.destination
	return
}

func (c *serverPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	if !c.responseWritten {
		_, err := c.ExtendedConn.Write([]byte{Version, 0})
		if err != nil {
			return err
		}
		c.responseWritten = true
	}
	packetLen := buffer.Len()
	binary.BigEndian.PutUint16(buffer.ExtendHeader(2), uint16(packetLen))
	return c.ExtendedConn.WriteBuffer(buffer)
}

func (c *serverPacketConn) FrontHeadroom() int {
	return 2
}

func (c *serverPacketConn) NeedAdditionalReadDeadline() bool {
	return true
}

func (c *serverPacketConn) Upstream() any {
	return c.ExtendedConn
}
