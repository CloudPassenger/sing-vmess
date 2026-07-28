package vmess

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"hash/crc32"
	"io"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/replay"
	"github.com/sagernet/sing/common/rw"

	"github.com/gofrs/uuid/v5"
)

type Handler interface {
	N.TCPConnectionHandlerEx
	N.UDPConnectionHandlerEx
}

var (
	ErrBadHeader    = E.New("bad header")
	ErrBadTimestamp = E.New("bad timestamp")
	ErrReplay       = E.New("replayed request")
	ErrBadRequest   = E.New("bad request")
	ErrBadVersion   = E.New("bad version")
)

const legacyUserRefreshInterval = 10 * time.Second

type Service[U comparable] struct {
	state                atomic.Pointer[serviceState[U]]
	replayFilter         replay.Filter
	handler              Handler
	time                 func() time.Time
	disableHeaderProtect bool
	refreshInterval      time.Duration
	lifecycleAccess      sync.Mutex
	refreshStop          chan struct{}
	refreshDone          chan struct{}
	started              bool
	closed               bool
}

type serviceState[U comparable] struct {
	users             []serviceUser[U]
	alterIDUpdateTime []int64
	legacyUserMap     map[[16]byte]legacyUserEntry[U]
	hasAlterIDs       bool
}

type serviceUser[U comparable] struct {
	user         U
	commandKey   [16]byte
	authIDCipher cipher.Block
	alterIDs     [][16]byte
}

type legacyUserEntry[U comparable] struct {
	User       U
	CommandKey [16]byte
	Time       int64
	Index      int
}

// PreparedUsers contains one complete immutable VMess authentication state.
type PreparedUsers[U comparable] struct {
	state *serviceState[U]
}

func NewService[U comparable](handler Handler, options ...ServiceOption) *Service[U] {
	service := &Service[U]{
		replayFilter:    replay.NewSimple(time.Second * 120),
		handler:         handler,
		time:            time.Now,
		refreshInterval: legacyUserRefreshInterval,
	}
	service.state.Store(&serviceState[U]{
		users:             make([]serviceUser[U], 0),
		alterIDUpdateTime: make([]int64, 0),
		legacyUserMap:     make(map[[16]byte]legacyUserEntry[U]),
	})
	anyService := (*Service[string])(unsafe.Pointer(service))
	for _, option := range options {
		option(anyService)
	}
	return service
}

func (s *Service[U]) UpdateUsers(userList []U, userIDList []string, alterIDList []int) error {
	prepared, err := s.PrepareUsers(userList, userIDList, alterIDList)
	if err != nil {
		return err
	}
	s.InstallUsers(prepared)
	return nil
}

// PrepareUsers validates and compiles one complete immutable VMess user state.
func (s *Service[U]) PrepareUsers(
	userList []U,
	userIDList []string,
	alterIDList []int,
) (*PreparedUsers[U], error) {
	if len(userList) != len(userIDList) || len(userList) != len(alterIDList) {
		return nil, E.New("invalid VMess user list lengths")
	}

	users := make([]serviceUser[U], 0, len(userList))
	credentialSet := make(map[uuid.UUID]struct{}, len(userList))
	var hasAlterIDs bool
	for index, user := range userList {
		userUUID, err := uuid.FromString(userIDList[index])
		if err != nil {
			userUUID = uuid.NewV5(uuid.Nil, userIDList[index])
		}
		if _, loaded := credentialSet[userUUID]; loaded {
			return nil, E.New("duplicate VMess UUID credential")
		}
		credentialSet[userUUID] = struct{}{}

		alterID := alterIDList[index]
		if alterID < 0 {
			return nil, E.New("invalid VMess alter ID at user index ", index)
		}

		commandKey := Key(userUUID)
		authIDCipher, err := aes.NewCipher(KDF(commandKey[:], KDFSaltConstAuthIDEncryptionKey)[:16])
		if err != nil {
			return nil, E.Cause(err, "create VMess authentication cipher")
		}

		alterIDs := make([][16]byte, 0, alterID)
		currentID := userUUID
		for range alterID {
			currentID = AlterId(currentID)
			alterIDs = append(alterIDs, currentID)
		}
		if alterID > 0 {
			hasAlterIDs = true
		}

		users = append(users, serviceUser[U]{
			user:         user,
			commandKey:   commandKey,
			authIDCipher: authIDCipher,
			alterIDs:     alterIDs,
		})
	}

	state := &serviceState[U]{
		users:             users,
		alterIDUpdateTime: make([]int64, len(users)),
		legacyUserMap:     make(map[[16]byte]legacyUserEntry[U]),
		hasAlterIDs:       hasAlterIDs,
	}
	if hasAlterIDs {
		state = buildLegacyUserState(state, s.time().Unix())
	}
	return &PreparedUsers[U]{state: state}, nil
}

// InstallUsers atomically publishes a prepared VMess authentication state.
func (s *Service[U]) InstallUsers(prepared *PreparedUsers[U]) {
	if prepared == nil || prepared.state == nil {
		return
	}
	s.state.Store(prepared.state)
}

func (s *Service[U]) Start() error {
	s.lifecycleAccess.Lock()
	defer s.lifecycleAccess.Unlock()
	if s.started || s.closed {
		return nil
	}

	refreshInterval := s.refreshInterval
	if refreshInterval <= 0 {
		refreshInterval = legacyUserRefreshInterval
	}
	s.refreshStop = make(chan struct{})
	s.refreshDone = make(chan struct{})
	s.started = true
	go s.loopGenerateLegacyKeys(refreshInterval, s.refreshStop, s.refreshDone)
	return nil
}

func (s *Service[U]) Close() error {
	s.lifecycleAccess.Lock()
	if s.closed {
		refreshDone := s.refreshDone
		s.lifecycleAccess.Unlock()
		if refreshDone != nil {
			<-refreshDone
		}
		return nil
	}
	s.closed = true
	refreshStop := s.refreshStop
	refreshDone := s.refreshDone
	s.lifecycleAccess.Unlock()

	if refreshStop != nil {
		close(refreshStop)
	}
	if refreshDone != nil {
		<-refreshDone
	}
	return nil
}

// The lifecycle goroutine remains until Close, but a state without alter IDs
// makes every refresh tick a lock-free, allocation-free no-op.
func (s *Service[U]) loopGenerateLegacyKeys(
	refreshInterval time.Duration,
	refreshStop <-chan struct{},
	refreshDone chan<- struct{},
) {
	refreshTicker := time.NewTicker(refreshInterval)
	defer refreshTicker.Stop()
	defer close(refreshDone)
	for {
		select {
		case <-refreshStop:
			return
		case <-refreshTicker.C:
			s.refreshLegacyKeys()
		}
	}
}

func (s *Service[U]) refreshLegacyKeys() bool {
	currentState := s.state.Load()
	if currentState == nil || !currentState.hasAlterIDs {
		return false
	}
	return s.refreshLegacyKeysFrom(currentState, s.time().Unix())
}

func (s *Service[U]) refreshLegacyKeysFrom(currentState *serviceState[U], nowSec int64) bool {
	if currentState == nil || !currentState.hasAlterIDs {
		return false
	}
	updatedState := buildLegacyUserState(currentState, nowSec)
	return s.state.CompareAndSwap(currentState, updatedState)
}

func buildLegacyUserState[U comparable](currentState *serviceState[U], nowSec int64) *serviceState[U] {
	endSec := nowSec + CacheDurationSeconds
	legacyUserMap := make(map[[16]byte]legacyUserEntry[U])
	alterIDUpdateTime := make([]int64, len(currentState.users))
	var hashValue [16]byte

	for userIndex, user := range currentState.users {
		if len(user.alterIDs) == 0 {
			continue
		}
		beginSec := currentState.alterIDUpdateTime[userIndex]
		if beginSec < nowSec-CacheDurationSeconds {
			beginSec = nowSec - CacheDurationSeconds
		}
		for alterIDIndex, alterID := range user.alterIDs {
			idHash := hmac.New(md5.New, alterID[:])
			for timestamp := beginSec; timestamp <= endSec; timestamp++ {
				common.Must(binary.Write(idHash, binary.BigEndian, uint64(timestamp)))
				idHash.Sum(hashValue[:0])
				idHash.Reset()
				legacyUserMap[hashValue] = legacyUserEntry[U]{
					User:       user.user,
					CommandKey: user.commandKey,
					Time:       timestamp,
					Index:      alterIDIndex,
				}
			}
		}
		alterIDUpdateTime[userIndex] = nowSec
	}

	return &serviceState[U]{
		users:             currentState.users,
		alterIDUpdateTime: alterIDUpdateTime,
		legacyUserMap:     legacyUserMap,
		hasAlterIDs:       currentState.hasAlterIDs,
	}
}

func (s *Service[U]) NewConnection(ctx context.Context, conn net.Conn, source M.Socksaddr, onClose N.CloseHandlerFunc) error {
	state := s.state.Load()
	const headerLenBufferLen = 2 + CipherOverhead
	const aeadMinHeaderLen = 16 + headerLenBufferLen + 8 + CipherOverhead + 42
	minHeaderLen := aeadMinHeaderLen
	if state.hasAlterIDs {
		minHeaderLen = 16 + 38
	}

	requestBuffer := buf.New()
	defer requestBuffer.Release()

	if !s.disableHeaderProtect {
		n, err := requestBuffer.ReadOnceFrom(conn)
		if err != nil {
			return err
		}
		if n < minHeaderLen {
			return ErrBadHeader
		}
	} else {
		_, err := requestBuffer.ReadAtLeastFrom(conn, minHeaderLen)
		if err != nil {
			return err
		}
	}

	authId := requestBuffer.To(16)
	var decodedID [16]byte
	var user U
	var commandKey [16]byte
	var found bool
	nowSec := s.time().Unix()
	for _, currentUser := range state.users {
		currentUser.authIDCipher.Decrypt(decodedID[:], authId)
		timestamp := int64(binary.BigEndian.Uint64(decodedID[:]))
		checksum := binary.BigEndian.Uint32(decodedID[12:])
		if crc32.ChecksumIEEE(decodedID[:12]) != checksum {
			continue
		}
		if math.Abs(math.Abs(float64(timestamp))-float64(nowSec)) > 120 {
			return ErrBadTimestamp
		}
		if !s.replayFilter.Check(decodedID[:]) {
			return ErrReplay
		}
		user = currentUser.user
		commandKey = currentUser.commandKey
		found = true
		break
	}

	var legacyProtocol bool
	var legacyTimestamp uint64
	if !found {
		copy(decodedID[:], authId)
		if currentUser, loaded := state.legacyUserMap[decodedID]; loaded {
			found = true
			legacyProtocol = true
			user = currentUser.User
			commandKey = currentUser.CommandKey
			legacyTimestamp = uint64(currentUser.Time)
		}
	}
	if !found {
		return ErrBadRequest
	}

	ctx = auth.ContextWithUser(ctx, user)
	cmdKey := commandKey
	var headerReader io.Reader
	var headerBuffer []byte

	var reader io.Reader
	var err error
	if legacyProtocol {
		requestBuffer.Advance(16)
		reader = io.MultiReader(bytes.NewReader(requestBuffer.Bytes()), conn)

		timeHash := md5.New()
		common.Must(binary.Write(timeHash, binary.BigEndian, legacyTimestamp))
		common.Must(binary.Write(timeHash, binary.BigEndian, legacyTimestamp))
		common.Must(binary.Write(timeHash, binary.BigEndian, legacyTimestamp))
		common.Must(binary.Write(timeHash, binary.BigEndian, legacyTimestamp))
		userKey := commandKey
		headerReader = NewStreamReader(reader, userKey[:], timeHash.Sum(nil))
		headerBuffer = make([]byte, 38)
		_, err = io.ReadFull(headerReader, headerBuffer)
		if err != nil {
			return E.Extend(ErrBadHeader, io.ErrShortBuffer)
		}
	} else {
		if requestBuffer.Len() < aeadMinHeaderLen {
			return ErrBadHeader
		}

		reader = conn

		const nonceIndex = 16 + headerLenBufferLen
		connectionNonce := requestBuffer.Range(nonceIndex, nonceIndex+8)

		lengthKey := KDF(cmdKey[:], KDFSaltConstVMessHeaderPayloadLengthAEADKey, authId, connectionNonce)[:16]
		lengthNonce := KDF(cmdKey[:], KDFSaltConstVMessHeaderPayloadLengthAEADIV, authId, connectionNonce)[:12]
		lengthBuffer, err := newAesGcm(lengthKey).Open(requestBuffer.Index(16), lengthNonce, requestBuffer.Range(16, nonceIndex), authId)
		if err != nil {
			return err
		}

		const headerIndex = nonceIndex + 8
		headerLength := int(binary.BigEndian.Uint16(lengthBuffer))
		needRead := headerLength + headerIndex + CipherOverhead - requestBuffer.Len()
		if needRead > 0 {
			_, err = requestBuffer.ReadFullFrom(conn, needRead)
			if err != nil {
				return err
			}
		}

		headerKey := KDF(cmdKey[:], KDFSaltConstVMessHeaderPayloadAEADKey, authId, connectionNonce)[:16]
		headerNonce := KDF(cmdKey[:], KDFSaltConstVMessHeaderPayloadAEADIV, authId, connectionNonce)[:12]
		headerBuffer, err = newAesGcm(headerKey).Open(requestBuffer.Index(headerIndex), headerNonce, requestBuffer.Range(headerIndex, headerIndex+headerLength+CipherOverhead), authId)
		if err != nil {
			return err
		}
		// replace with < if support mux
		if len(headerBuffer) <= 38 {
			return E.Extend(ErrBadHeader, io.ErrShortBuffer)
		}
		requestBuffer.Advance(headerIndex + headerLength + CipherOverhead)
		headerReader = bytes.NewReader(headerBuffer[38:])
	}

	version := headerBuffer[0]
	if version != Version {
		return E.Extend(ErrBadVersion, version)
	}

	requestBodyKey := make([]byte, 16)
	requestBodyNonce := make([]byte, 16)

	copy(requestBodyKey, headerBuffer[17:33])
	copy(requestBodyNonce, headerBuffer[1:17])

	responseHeader := headerBuffer[33]
	option := headerBuffer[34]
	paddingLen := int(headerBuffer[35] >> 4)
	security := headerBuffer[35] & 0x0F
	switch security {
	case SecurityTypeNone, SecurityTypeLegacy, SecurityTypeAes128Gcm, SecurityTypeChacha20Poly1305:
	default:
		return E.New("unknown security type: ", security)
	}
	command := headerBuffer[37]
	switch command {
	case CommandTCP, CommandUDP, CommandMux:
	default:
		return E.New("unknown command: ", command)
	}
	if command == CommandUDP && option == 0 {
		return E.New("bad packet connection")
	}
	var destination M.Socksaddr
	if command != CommandMux {
		destination, err = AddressSerializer.ReadAddrPort(headerReader)
		if err != nil {
			return err
		}
	}
	if paddingLen > 0 {
		_, err = io.CopyN(io.Discard, headerReader, int64(paddingLen))
		if err != nil {
			return E.Extend(ErrBadHeader, "bad padding")
		}
	}
	err = rw.SkipN(headerReader, 4)
	if err != nil {
		return err
	}
	if !legacyProtocol && requestBuffer.Len() > 0 {
		reader = bufio.NewCachedReader(reader, requestBuffer.ToOwned())
	}
	reader = CreateReader(reader, nil, requestBodyKey, requestBodyNonce, requestBodyKey, requestBodyNonce, security, option)
	if option&RequestOptionChunkStream != 0 && command == CommandTCP || command == CommandMux {
		reader = bufio.NewChunkReader(reader, ReadChunkSize)
	}
	rawConn := rawServerConn{
		Conn:           conn,
		legacyProtocol: legacyProtocol,
		requestKey:     requestBodyKey,
		requestNonce:   requestBodyNonce,
		responseHeader: responseHeader,
		security:       security,
		option:         option,
		reader:         bufio.NewExtendedReader(reader),
	}

	switch command {
	case CommandTCP:
		s.handler.NewConnectionEx(ctx, &serverConn{rawConn}, source, destination, onClose)
	case CommandUDP:
		s.handler.NewPacketConnectionEx(ctx, &serverPacketConn{rawConn, destination}, source, destination, onClose)
	case CommandMux:
		return HandleMuxConnection(ctx, &serverConn{rawConn}, source, s.handler)
	default:
		return E.New("unknown command: ", command)
	}
	return nil
}

var _ N.EarlyWriter = (*rawServerConn)(nil)

type rawServerConn struct {
	net.Conn
	legacyProtocol bool
	requestKey     []byte
	requestNonce   []byte
	responseHeader byte
	security       byte
	option         byte
	reader         N.ExtendedReader
	writer         N.ExtendedWriter
}

func (c *rawServerConn) writeResponse() error {
	if c.legacyProtocol {
		responseKey := md5.Sum(c.requestKey)
		responseNonce := md5.Sum(c.requestNonce)
		headerWriter := NewStreamWriter(c.Conn, responseKey[:], responseNonce[:])
		_, err := headerWriter.Write([]byte{c.responseHeader, c.option, 0, 0})
		if err != nil {
			return E.Cause(err, "write response")
		}
		c.writer = bufio.NewExtendedWriter(CreateWriter(c.Conn, headerWriter, c.requestKey, c.requestNonce, responseKey[:], responseNonce[:], c.security, c.option))
	} else {
		responseBuffer := buf.NewSize(2 + CipherOverhead + 4 + CipherOverhead)
		defer responseBuffer.Release()

		_responseKey := sha256.Sum256(c.requestKey[:])
		responseKey := _responseKey[:16]
		_responseNonce := sha256.Sum256(c.requestNonce[:])
		responseNonce := _responseNonce[:16]

		headerLenKey := KDF(responseKey, KDFSaltConstAEADRespHeaderLenKey)[:16]
		headerLenNonce := KDF(responseNonce, KDFSaltConstAEADRespHeaderLenIV)[:12]
		headerLenCipher := newAesGcm(headerLenKey)
		binary.BigEndian.PutUint16(responseBuffer.Extend(2), 4)
		headerLenCipher.Seal(responseBuffer.Index(0), headerLenNonce, responseBuffer.Bytes(), nil)
		responseBuffer.Extend(CipherOverhead)

		headerKey := KDF(responseKey, KDFSaltConstAEADRespHeaderPayloadKey)[:16]
		headerNonce := KDF(responseNonce, KDFSaltConstAEADRespHeaderPayloadIV)[:12]
		headerCipher := newAesGcm(headerKey)
		common.Must(
			responseBuffer.WriteByte(c.responseHeader),
			responseBuffer.WriteByte(c.option),
			responseBuffer.WriteZeroN(2),
		)
		const headerIndex = 2 + CipherOverhead
		headerCipher.Seal(responseBuffer.Index(headerIndex), headerNonce, responseBuffer.From(headerIndex), nil)
		responseBuffer.Extend(CipherOverhead)

		_, err := c.Conn.Write(responseBuffer.Bytes())
		if err != nil {
			return err
		}

		c.writer = bufio.NewExtendedWriter(CreateWriter(c.Conn, nil, c.requestKey, c.requestNonce, responseKey, responseNonce, c.security, c.option))
	}
	return nil
}

func (c *rawServerConn) Close() error {
	return common.Close(
		c.Conn,
		c.reader,
	)
}

func (c *rawServerConn) FrontHeadroom() int {
	return MaxFrontHeadroom
}

func (c *rawServerConn) RearHeadroom() int {
	return MaxRearHeadroom
}

func (c *rawServerConn) ReaderOverhead() int {
	return ReaderOverhead(c.security, c.option)
}

func (c *rawServerConn) NeedHandshakeForWrite() bool {
	return c.writer == nil
}

func (c *rawServerConn) NeedAdditionalReadDeadline() bool {
	return true
}

func (c *rawServerConn) Upstream() any {
	return c.Conn
}

type serverConn struct {
	rawServerConn
}

func (c *serverConn) Read(b []byte) (n int, err error) {
	return c.reader.Read(b)
}

func (c *serverConn) Write(b []byte) (n int, err error) {
	if c.writer == nil {
		err = c.writeResponse()
		if err != nil {
			return
		}
	}
	return c.writer.Write(b)
}

func (c *serverConn) ReadBuffer(buffer *buf.Buffer) error {
	return c.reader.ReadBuffer(buffer)
}

func (c *serverConn) WriteBuffer(buffer *buf.Buffer) error {
	if c.writer == nil {
		err := c.writeResponse()
		if err != nil {
			buffer.Release()
			return err
		}
	}
	return c.writer.WriteBuffer(buffer)
}

func (c *serverConn) WriteTo(w io.Writer) (n int64, err error) {
	return bufio.Copy(w, c.reader)
}

func (c *serverConn) ReadFrom(r io.Reader) (n int64, err error) {
	if c.writer == nil {
		err = c.writeResponse()
		if err != nil {
			return
		}
	}
	return bufio.Copy(c.writer, r)
}

var _ PacketConn = (*serverPacketConn)(nil)

type serverPacketConn struct {
	rawServerConn
	destination M.Socksaddr
}

func (c *serverPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, err = c.reader.Read(p)
	if err != nil {
		return
	}
	addr = c.destination.UDPAddr()
	return
}

func (c *serverPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if c.writer == nil {
		err = c.writeResponse()
		if err != nil {
			return
		}
	}
	return c.writer.Write(p)
}

func (c *serverPacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	err = c.reader.ReadBuffer(buffer)
	if err != nil {
		return
	}
	destination = c.destination
	return
}

func (c *serverPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	if c.writer == nil {
		err := c.writeResponse()
		if err != nil {
			return err
		}
	}
	return c.writer.WriteBuffer(buffer)
}
