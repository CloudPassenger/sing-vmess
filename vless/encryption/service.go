package encryption

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/ntp"

	"lukechampine.com/blake3"
)

type ServiceSession struct {
	PfsKey  []byte
	NfsKeys sync.Map
}

type Service struct {
	ctx    context.Context
	closed chan struct{}

	NfsSKeys      []any
	NfsPKeysBytes [][]byte
	Hash32s       [][Hash256Length]byte
	RelaysLength  int
	XorMode       XorMode
	SecondsFrom   int64
	SecondsTo     int64
	PaddingLens   [][3]int
	PaddingGaps   [][3]int

	sessionAccess sync.RWMutex
	timeFunc      func() time.Time
	Lasts         map[int64][TicketLength]byte
	Tickets       [][TicketLength]byte
	Sessions      map[[TicketLength]byte]*ServiceSession
}

func NewService(ctx context.Context, nfsSKeysBytes [][]byte, xorMode XorMode, secondsFrom, secondsTo int64, padding []string) (*Service, error) {
	if len(nfsSKeysBytes) == 0 {
		return nil, E.New("nfsSKeysBytes must not be empty")
	}
	service := &Service{
		ctx:           ctx,
		NfsSKeys:      make([]any, len(nfsSKeysBytes)),
		NfsPKeysBytes: make([][]byte, len(nfsSKeysBytes)),
		Hash32s:       make([][Hash256Length]byte, len(nfsSKeysBytes)),
		XorMode:       xorMode,
		SecondsFrom:   secondsFrom,
		SecondsTo:     secondsTo,
		timeFunc:      ntp.TimeFuncFromContext(ctx),
	}
	if service.timeFunc == nil {
		service.timeFunc = time.Now
	}
	for i, keyBytes := range nfsSKeysBytes {
		switch len(keyBytes) {
		case X25519KeySize:
			key, err := ecdh.X25519().NewPrivateKey(keyBytes)
			if err != nil {
				return nil, E.Cause(err, "initialize x25519 private key of ", i)
			}
			service.NfsSKeys[i] = key
			service.NfsPKeysBytes[i] = key.PublicKey().Bytes()
			service.RelaysLength += X25519KeySize + Hash256Length
		case mlkem.SeedSize:
			key, err := mlkem.NewDecapsulationKey768(keyBytes)
			if err != nil {
				return nil, E.Cause(err, "initialize mlkem decapsulation key of ", i)
			}
			service.NfsSKeys[i] = key
			service.NfsPKeysBytes[i] = key.EncapsulationKey().Bytes()
			service.RelaysLength += mlkem.CiphertextSize768 + Hash256Length
		default:
			return nil, E.New("invalid key size: ", len(keyBytes))
		}
		service.Hash32s[i] = blake3.Sum256(service.NfsPKeysBytes[i])
	}
	service.RelaysLength -= Hash256Length
	var err error
	service.PaddingLens, service.PaddingGaps, err = ParsePadding(padding)
	if err != nil {
		return nil, err
	}
	return service, nil
}

func ParseDecryption(raw string) (xorMode XorMode, secondsFrom, secondsTo int64, nfsKeyBytes [][]byte, paddings []string, err error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 4 {
		err = E.New("malformed decryption")
		return
	}

	decryptionType := parts[0]
	if decryptionType != "mlkem768x25519plus" {
		err = E.New("unknown decryption type: ", decryptionType)
		return
	}

	rawXorMode := parts[1]
	switch rawXorMode {
	case "native":
		xorMode = XorModeNative
	case "xorpub":
		xorMode = XorModeXorPub
	case "random":
		xorMode = XorModeRandom
	default:
		err = E.New("unknown xor mode: ", rawXorMode)
		return
	}

	rawTimes := parts[2]
	timeParts := strings.SplitN(strings.TrimSuffix(rawTimes, "s"), ".", 2)
	rawFrom := timeParts[0]
	from, err := strconv.Atoi(rawFrom)
	if err != nil {
		err = E.Cause(err, "parse seconds from: ", rawFrom)
	}
	secondsFrom = int64(from)
	if len(timeParts) == 2 {
		rawTo := timeParts[1]
		var to int
		to, err = strconv.Atoi(timeParts[1])
		if err != nil {
			err = E.Cause(err, "parse seconds to: ", rawTo)
		}
		secondsTo = int64(to)
	}

	paddingParts := parts[3:]
	for i, rawPadding := range paddingParts {
		if len(rawPadding) < 20 {
			paddings = append(paddings, rawPadding)
			continue
		}
		var decoded []byte
		decoded, err = base64.RawURLEncoding.DecodeString(rawPadding)
		if err != nil {
			err = E.Cause(err, "base64 decode for: ", i)
		}
		switch len(decoded) {
		case X25519KeySize:
		case mlkem.SeedSize:
		default:
			err = E.New("invalid key size ", len(decoded), " of ", i)
			return
		}
		nfsKeyBytes = append(nfsKeyBytes, decoded)
	}

	return
}

func (s *Service) Start() error {
	if s.allow0Rtt() {
		go s.loopCleanLegacySessions()
	}
	return nil
}

func (s *Service) loopCleanLegacySessions() {
	s.closed = make(chan struct{})
	s.Lasts = make(map[int64][TicketLength]byte)
	s.Tickets = make([][TicketLength]byte, 0, 1024)
	s.Sessions = make(map[[TicketLength]byte]*ServiceSession)

	const CLeanDuration = 1 * time.Minute
	timer := time.NewTimer(CLeanDuration)
	for {
		timer.Reset(CLeanDuration)
		select {
		case <-s.ctx.Done():
			return
		case <-s.closed:
			return
		case <-timer.C:
		}
		s.sessionAccess.Lock()
		minute := s.timeFunc().Unix() / 60
		last := s.Lasts[minute]
		delete(s.Lasts, minute)
		delete(s.Lasts, minute-1) // for insurance
		if !common.IsEmpty(last) {
			for i, ticker := range s.Tickets {
				delete(s.Sessions, ticker)
				if ticker == last {
					s.Tickets = s.Tickets[i+1:]
					break
				}
			}
		}
		s.sessionAccess.Unlock()
	}
}

func (s *Service) allow0Rtt() bool {
	return s.SecondsFrom > 0 || s.SecondsTo > 0
}

func (s *Service) Close() error {
	s.sessionAccess.Lock()
	defer s.sessionAccess.Unlock()
	close(s.closed)
	return nil
}

func (s *Service) Handshake(conn net.Conn, fallback *[]byte) (*CommonConn, error) {
	commonConn := NewCommonConn(conn, true)

	ivAndRelays := buf.NewSize(IVLength + s.RelaysLength)
	defer ivAndRelays.Release()
	_, err := ivAndRelays.ReadFullFrom(conn, ivAndRelays.Cap())
	if err != nil {
		return nil, err
	}
	if fallback != nil {
		*fallback = append(*fallback, ivAndRelays.Bytes()...)
	}
	iv := ivAndRelays.To(IVLength)
	relays := ivAndRelays.From(IVLength)
	var (
		nfsKey  []byte
		lastCTR cipher.Stream
	)
	for i, key := range s.NfsSKeys {
		if lastCTR != nil {
			lastCTR.XORKeyStream(relays, relays[:EncryptedTicketLength]) // recover this relay
		}
		var index int
		switch key.(type) {
		case *ecdh.PrivateKey:
			index = X25519KeySize
		case *mlkem.DecapsulationKey768:
			index = mlkem.CiphertextSize768
		default:
			panic("unexcepted key type")
		}
		if s.XorMode != XorModeNative {
			NewCTR(s.NfsPKeysBytes[i], iv).XORKeyStream(relays, relays[:index]) // we don't use buggy elligator2, because we have PSK :)
		}
		switch key.(type) {
		case *ecdh.PrivateKey:
			publicKey, err := ecdh.X25519().NewPublicKey(relays[:index])
			if err != nil {
				return nil, E.Cause(err, "initialize x25519 public key of ", i)
			}
			if publicKey.Bytes()[31] > 127 { // we just don't want the observer can change even one bit without breaking the connection, though it has nothing to do with security
				return nil, E.New("x25519 key ", i, ": the highest bit of the last byte of the peer-sent X25519 public key is not 0")
			}
			x25519Key := key.(*ecdh.PrivateKey)
			nfsKey, err = x25519Key.ECDH(publicKey)
			if err != nil {
				return nil, E.Cause(err, "create nfs key from x25519 public key of ", i)
			}
		case *mlkem.DecapsulationKey768:
			mlkemKey := key.(*mlkem.DecapsulationKey768)
			nfsKey, err = mlkemKey.Decapsulate(relays[:index])
			if err != nil {
				return nil, E.Cause(err, "create nfs key from mlkem public key of ", i)
			}
		default:
			panic("unexcepted key type")
		}
		if i == len(s.NfsSKeys)-1 {
			break
		}
		relays = relays[index:]
		lastCTR = NewCTR(nfsKey, iv)
		lastCTR.XORKeyStream(relays, relays[:Hash256Length])
		if !bytes.Equal(relays[:Hash256Length], s.Hash32s[i+1][:]) {
			return nil, E.New("unexpected hash 32: ", fmt.Sprint(relays[:Hash256Length]))
		}
		relays = relays[Hash256Length:]
	}
	nfsAead := NewAEAD(iv, nfsKey, commonConn.UseAES)

	encryptedLength := make([]byte, 2+nfsAead.Overhead())
	_, err = io.ReadFull(conn, encryptedLength)
	if err != nil {
		return nil, err
	}
	if fallback != nil {
		*fallback = append(*fallback, encryptedLength...)
	}
	decryptedLength := make([]byte, 2)
	if _, err0 := nfsAead.Open(decryptedLength[:0], nil, encryptedLength, nil); err0 != nil {
		commonConn.UseAES = !commonConn.UseAES
		nfsAead = NewAEAD(iv, nfsKey, commonConn.UseAES)
		if _, err1 := nfsAead.Open(decryptedLength[:0], nil, encryptedLength, nil); err1 != nil {
			return nil, E.Cause(E.Errors(err0, err1), "try decrypt length with aes and chacha20")
		}
	}
	if fallback != nil {
		*fallback = nil
	}
	length := binary.BigEndian.Uint16(decryptedLength)

	if length == EncryptedTicketLength {
		if !s.allow0Rtt() {
			return nil, E.New("0-rtt is forbidden")
		}
		encryptedTicket := make([]byte, EncryptedTicketLength)
		_, err = io.ReadFull(conn, encryptedTicket)
		if err != nil {
			return nil, err
		}
		ticket, err := nfsAead.Open(nil, nil, encryptedTicket, nil)
		if err != nil {
			return nil, E.Cause(err, "open encrypted ticket")
		}
		s.sessionAccess.Lock()
		session := s.Sessions[[TicketLength]byte(ticket)]
		s.sessionAccess.Unlock()
		if session == nil {
			noises := buf.NewSize(int(randBetween(1279, 2279))) // matches 1-RTT's server hello length for "random", though it is not important, just for example
			defer noises.Release()
			// Prevent valid header
			header := noises.To(HeaderLength)
			var err error
			for err == nil {
				rand.Read(header)
				_, err = DecodeHeader(header)
			}
			noises.Truncate(HeaderLength)
			noises.ReadFullFrom(rand.Reader, noises.FreeLen())
			_, _ = conn.Write(noises.Bytes()) // make client do new handshake
			return nil, E.New("expired ticket")
		}
		if _, loaded := session.NfsKeys.Load([EncryptedTicketLength]byte(nfsKey)); loaded { // prevents bad client also
			return nil, E.New("replay detected!")
		}
		commonConn.UnitedKey = append(session.PfsKey, nfsKey...) // the same nfsKey links the upload & download (prevents server -> client's another request)
		commonConn.PreWrite = make([]byte, TicketLength)
		rand.Read(commonConn.PreWrite) // always trust yourself, not the client (also prevents being parsed as TLS thus causing false interruption for "native" and "xorpub")
		commonConn.AEAD = NewAEAD(commonConn.PreWrite, commonConn.UnitedKey, commonConn.UseAES)
		commonConn.PeerAEAD = NewAEAD(encryptedTicket, commonConn.UnitedKey, commonConn.UseAES) // unchangeable ctx (prevents server -> server), and different ctx length for upload / download (prevents client -> client)
		if s.XorMode == XorModeRandom {
			commonConn.Conn = NewXorConn(conn, NewCTR(commonConn.UnitedKey, commonConn.PreWrite), NewCTR(commonConn.UnitedKey, iv), 16, 0) // it doesn't matter if the attacker sends client's iv back to the client
		}
		return commonConn, nil
	}

	if length < EncryptedPfsPublicKeyLength { // client may send more public keys in the future's version
		return nil, io.ErrUnexpectedEOF
	}
	encryptedPfsPublicKey := buf.NewSize(int(length))
	defer encryptedPfsPublicKey.Release()
	_, err = encryptedPfsPublicKey.ReadFullFrom(conn, encryptedPfsPublicKey.FreeLen())
	if err != nil {
		return nil, err
	}
	_, err = nfsAead.Open(encryptedPfsPublicKey.Index(0), nil, encryptedPfsPublicKey.Bytes(), nil)
	if err != nil {
		return nil, E.Cause(err, "open encrypted public key")
	}
	mlkem768EKey, err := mlkem.NewEncapsulationKey768(encryptedPfsPublicKey.To(mlkem.EncapsulationKeySize768))
	if err != nil {
		return nil, E.Cause(err, "create mlkem768 key from encryptedPfsPublicKey")
	}
	mlkem768Key, encapsulatedPfsKey := mlkem768EKey.Encapsulate()
	peerX25519Key, err := ecdh.X25519().NewPublicKey(encryptedPfsPublicKey.Range(mlkem.EncapsulationKeySize768, mlkem.EncapsulationKeySize768+X25519KeySize))
	if err != nil {
		return nil, E.Cause(err, "create x25519 public key from encryptedPfsPublicKey")
	}
	x25519SKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
	x25519Key, err := x25519SKey.ECDH(peerX25519Key)
	if err != nil {
		return nil, E.Cause(err, "x25519 ecdh")
	}
	pfsKey := append(mlkem768Key, x25519Key...)
	pfsPublicKey := append(encapsulatedPfsKey, x25519SKey.PublicKey().Bytes()...)
	commonConn.UnitedKey = append(pfsKey, nfsKey...)
	commonConn.AEAD = NewAEAD(pfsPublicKey, commonConn.UnitedKey, commonConn.UseAES)
	commonConn.PeerAEAD = NewAEAD(encryptedPfsPublicKey.To(mlkem.EncapsulationKeySize768+EncryptedTicketLength), commonConn.UnitedKey, commonConn.UseAES)

	ticket := [TicketLength]byte{}
	rand.Read(ticket[:])
	var seconds int64
	if s.SecondsTo == 0 {
		seconds = s.SecondsFrom * randBetween(50, 100) / 100
	} else {
		seconds = randBetween(s.SecondsFrom, s.SecondsTo)
	}
	binary.BigEndian.PutUint16(ticket[:], uint16(seconds))
	if seconds > 0 {
		s.sessionAccess.Lock()
		s.Lasts[(s.timeFunc().Unix()+max(s.SecondsFrom, s.SecondsTo))/60+2] = ticket
		s.Tickets = append(s.Tickets, ticket)
		s.Sessions[ticket] = &ServiceSession{PfsKey: pfsKey}
		s.sessionAccess.Unlock()
	}

	paddingLength, paddingLens, paddingGaps := CreatePadding(s.PaddingLens, s.PaddingGaps)
	serverHello := buf.NewSize(EncryptedPfsPublicKeyLength + EncryptedTicketLength + paddingLength)
	defer serverHello.Release()
	nfsAead.Seal(serverHello.Index(0), MaxNonce, pfsPublicKey, nil)
	commonConn.AEAD.Seal(serverHello.Index(EncryptedPfsPublicKeyLength), nil, ticket[:], nil)
	const paddingIndex = EncryptedPfsPublicKeyLength + EncryptedTicketLength
	commonConn.AEAD.Seal(serverHello.Index(paddingIndex), nil, binary.BigEndian.AppendUint16(nil, uint16(paddingLength-18)), nil)
	commonConn.AEAD.Seal(serverHello.Index(paddingIndex+EncryptedLengthSize), nil, serverHello.Range(paddingIndex+18, paddingIndex+paddingLength-16), nil)
	serverHello.Truncate(serverHello.Cap())

	paddingLens[0] += paddingIndex
	for i, paddingLen := range paddingLens { // sends padding in a fragmented way, to create variable traffic pattern, before inner VLESS flow takes control
		if paddingLen > 0 {
			_, err = conn.Write(serverHello.To(paddingLen))
			if err != nil {
				return nil, E.Cause(err, "write padding ", i)
			}
			serverHello.Advance(paddingLen)
		}
		if len(paddingGaps) > i {
			time.Sleep(paddingGaps[i])
		}
	}

	// important: allows client sends padding slowly, eliminating 1-RTT's traffic pattern
	_, err = io.ReadFull(conn, encryptedLength)
	if err != nil {
		return nil, err
	}
	_, err = nfsAead.Open(encryptedLength[:0], nil, encryptedLength, nil)
	if err != nil {
		return nil, E.Cause(err, "open encrypted length")
	}
	encryptedPadding := buf.NewSize(int(binary.BigEndian.Uint16(encryptedLength)))
	defer encryptedPadding.Release()
	_, err = encryptedPadding.ReadFullFrom(conn, encryptedPadding.Cap())
	if err != nil {
		return nil, err
	}
	_, err = nfsAead.Open(encryptedPadding.Index(0), nil, encryptedPadding.Bytes(), nil)
	if err != nil {
		return nil, E.Cause(err, "open encrypted padding")
	}

	if s.XorMode == XorModeRandom {
		commonConn.Conn = NewXorConn(conn, NewCTR(commonConn.UnitedKey, ticket[:]), NewCTR(commonConn.UnitedKey, iv), 0, 0)
	}

	return commonConn, nil
}
