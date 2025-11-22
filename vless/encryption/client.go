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
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/ntp"

	"lukechampine.com/blake3"
)

const (
	// PFS key exchange related lengths
	PfsKeyExchangeLength = EncryptedLengthSize + mlkem.EncapsulationKeySize768 + X25519KeySize + AEADTagLength // 18 + 1184 + 32 + 16
	PfsKeySize           = Hash256Length + Hash256Length                                                       // ML-KEM-768 shared key + X25519 shared key
	PfsPublicKeyLength   = mlkem.EncapsulationKeySize768 + X25519KeySize                                       // 1184 + 32

	EncryptedPfsPublicKeyLength = mlkem.CiphertextSize768 + X25519KeySize + AEADTagLength // 1088 + 32 + 16
	EncryptedTicketLength       = Hash256Length                                           // 32
)

// XorMode represents the XOR encryption mode for obfuscation
type XorMode byte

const (
	XorModeNative XorMode = 0 // No XOR obfuscation
	XorModeXorPub XorMode = 1 // XOR obfuscation for public key/ciphertext only
	XorModeRandom XorMode = 2 // Full XOR obfuscation for all traffic
)

type Client struct {
	NfsPKeys      []any
	NfsPKeysBytes [][]byte
	Hash32s       [][Hash256Length]byte
	RelaysLength  int
	XorMode       XorMode
	Seconds       uint32
	PaddingLens   [][3]int
	PaddingGaps   [][3]int

	RWLock   sync.RWMutex
	timeFunc func() time.Time
	Expire   time.Time
	PfsKey   []byte
	Ticket   []byte
}

func NewClient(ctx context.Context, nfsPKeysBytes [][]byte, xorMode XorMode, seconds uint32, paddings []string) (client *Client, err error) {
	if len(nfsPKeysBytes) == 0 {
		return nil, E.New("empty nfsPKeysBytes")
	}
	client = &Client{
		NfsPKeys:      make([]any, len(nfsPKeysBytes)),
		NfsPKeysBytes: nfsPKeysBytes,
		Hash32s:       make([][Hash256Length]byte, len(nfsPKeysBytes)),
		XorMode:       xorMode,
		Seconds:       seconds,
		timeFunc:      ntp.TimeFuncFromContext(ctx),
	}
	if client.timeFunc == nil {
		client.timeFunc = time.Now
	}
	for i, keysByte := range nfsPKeysBytes {
		switch len(keysByte) {
		case X25519KeySize:
			if client.NfsPKeys[i], err = ecdh.X25519().NewPublicKey(keysByte); err != nil {
				return
			}
			client.RelaysLength += X25519KeySize + Hash256Length
		case mlkem.CiphertextSize768:
			if client.NfsPKeys[i], err = mlkem.NewEncapsulationKey768(keysByte); err != nil {
				return
			}
			client.RelaysLength += mlkem.CiphertextSize768 + Hash256Length
		default:
			return nil, E.New("invalid nfsPKeysBytes size of ", i)
		}
		client.Hash32s[i] = blake3.Sum256(keysByte)
	}
	client.RelaysLength -= Hash256Length
	client.PaddingLens, client.PaddingGaps, err = ParsePadding(paddings)
	if err != nil {
		return nil, err
	}
	return client, nil
}

func ParseEncryption(raw string) (xorMode XorMode, seconds uint32, nfsPKeysBytes [][]byte, paddings []string, err error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 4 {
		err = E.New("invalid encryption parts: ", len(parts))
		return
	}

	encryptionType := parts[0]
	if encryptionType != "mlkem768x25519plus" {
		err = E.New("unknown encryption type: ", encryptionType)
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
		err = E.New("unknown encryption mode: ", rawXorMode)
		return
	}

	rttPart := parts[2]
	switch rttPart {
	case "1rtt":
	case "0rtt":
		seconds = 1
	default:
		err = E.New("unknown rtt: ", rttPart)
		return
	}

	keyParts := parts[3:]
	for _, key := range keyParts {
		if len(key) < 20 {
			paddings = append(paddings, key)
			continue
		}
		var decoded []byte
		decoded, err = base64.RawURLEncoding.DecodeString(key)
		if err != nil {
			err = E.New("decode base64 of key: ", key)
			return
		}
		if len(decoded) != X25519KeySize && len(decoded) != mlkem.EncapsulationKeySize768 {
			err = E.New("invalid key length: ", key)
			return
		}
		nfsPKeysBytes = append(nfsPKeysBytes, decoded)
	}

	return
}

func (c *Client) Handshake(conn net.Conn) (commonConn *CommonConn, err error) {
	commonConn = NewCommonConn(conn, hasAESGCMHardwareSupport)

	ivAndRelaysLength := IVLength + c.RelaysLength
	pfsKeyExchangeLength := PfsKeyExchangeLength
	paddingLength, paddingLens, paddingGaps := CreatePadding(c.PaddingLens, c.PaddingGaps)
	clientHello := buf.NewSize(ivAndRelaysLength + pfsKeyExchangeLength + paddingLength)
	defer clientHello.Release()

	iv := clientHello.To(IVLength)
	rand.Read(iv)
	relays := clientHello.Index(IVLength)[:ivAndRelaysLength-IVLength]
	var nfsKey []byte
	var lastCTR cipher.Stream
	for i, key := range c.NfsPKeys {
		var index = X25519KeySize
		switch key.(type) {
		case *ecdh.PublicKey:
			x25519Key := key.(*ecdh.PublicKey)
			privateKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
			copy(relays, privateKey.PublicKey().Bytes())
			nfsKey, err = privateKey.ECDH(x25519Key)
			if err != nil {
				return nil, err
			}
		case *mlkem.EncapsulationKey768:
			mlkemKey := key.(*mlkem.EncapsulationKey768)
			var ciphertext []byte
			nfsKey, ciphertext = mlkemKey.Encapsulate()
			copy(relays, ciphertext)
			index = mlkem.CiphertextSize768
		default:
			panic("invalid key type")
		}
		if c.XorMode != XorModeNative { // this xor can (others can't) be recovered by client's config, revealing an X25519 public key / ML-KEM-768 ciphertext, that's why "native" values
			NewCTR(c.NfsPKeysBytes[i], iv).XORKeyStream(relays, relays[:index]) // make X25519 public key / ML-KEM-768 ciphertext distinguishable from random bytes
		}
		if lastCTR != nil {
			lastCTR.XORKeyStream(relays, relays[:Hash256Length]) // make this relay irreplaceable
		}
		if i == len(c.NfsPKeys)-1 {
			break
		}
		lastCTR = NewCTR(nfsKey, iv)
		lastCTR.XORKeyStream(relays[index:], c.Hash32s[i+1][:])
		relays = relays[index+Hash256Length:]
	}
	nfsAEAD := NewAEAD(iv, nfsKey, commonConn.UseAES)

	if c.Seconds > 0 {
		c.RWLock.RLock()
		if c.timeFunc().Before(c.Expire) {
			commonConn.Client = c
			commonConn.UnitedKey = append(c.PfsKey, nfsKey...) // different unitedKey for each connection
			nfsAEAD.Seal(clientHello.To(ivAndRelaysLength), nil, binary.BigEndian.AppendUint16(nil, EncryptedTicketLength), nil)
			nfsAEAD.Seal(clientHello.To(ivAndRelaysLength+EncryptedLengthSize), nil, c.Ticket, nil)
			c.RWLock.RUnlock()
			commonConn.PreWrite = bytes.Clone(clientHello.To(ivAndRelaysLength + EncryptedLengthSize + EncryptedTicketLength))
			commonConn.AEAD = NewAEAD(clientHello.Index(ivAndRelaysLength + EncryptedLengthSize)[:EncryptedTicketLength], commonConn.UnitedKey, commonConn.UseAES)
			if c.XorMode == XorModeRandom {
				commonConn.Conn = NewXorConn(conn, NewCTR(commonConn.UnitedKey, iv), nil, len(commonConn.PreWrite), IVLength)
			}
			return commonConn, nil
		}
		c.RWLock.RUnlock()
	}

	pfsKeyExchange := clientHello.Index(ivAndRelaysLength)[:pfsKeyExchangeLength]
	nfsAEAD.Seal(pfsKeyExchange[:0], nil, binary.BigEndian.AppendUint16(nil, uint16(pfsKeyExchangeLength-EncryptedLengthSize)), nil)
	mlkem768DKey, _ := mlkem.GenerateKey768()
	x25519SKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
	pfsPublicKey := append(mlkem768DKey.EncapsulationKey().Bytes(), x25519SKey.PublicKey().Bytes()...)
	nfsAEAD.Seal(pfsKeyExchange[:EncryptedLengthSize], nil, pfsPublicKey, nil)

	padding := clientHello.Index(ivAndRelaysLength + pfsKeyExchangeLength)
	nfsAEAD.Seal(padding[:0], nil, binary.BigEndian.AppendUint16(nil, uint16(paddingLength-EncryptedLengthSize)), nil)
	nfsAEAD.Seal(padding[:EncryptedLengthSize], nil, padding[EncryptedLengthSize:paddingLength-AEADTagLength], nil)

	offset := ivAndRelaysLength + pfsKeyExchangeLength
	for i, l := range paddingLens { // sends padding in a fragmented way, to create variable traffic pattern, before inner VLESS flow takes control
		writeLen := l
		if i == 0 {
			writeLen = offset + l
		}
		if writeLen > 0 {
			if i == 0 {
				clientHello.Resize(0, writeLen)
			} else {
				clientHello.Truncate(writeLen)
			}
			if _, err := conn.Write(clientHello.Bytes()[:writeLen]); err != nil {
				return nil, err
			}
			clientHello.Advance(writeLen)
		}
		if len(paddingGaps) > i {
			time.Sleep(paddingGaps[i])
		}
	}

	encryptedPfsPublicKey := make([]byte, EncryptedPfsPublicKeyLength)
	if _, err := io.ReadFull(conn, encryptedPfsPublicKey); err != nil {
		return nil, err
	}
	nfsAEAD.Open(encryptedPfsPublicKey[:0], MaxNonce, encryptedPfsPublicKey, nil)
	mlkem768Key, err := mlkem768DKey.Decapsulate(encryptedPfsPublicKey[:mlkem.CiphertextSize768])
	if err != nil {
		return nil, err
	}
	peerX25519PKey, err := ecdh.X25519().NewPublicKey(encryptedPfsPublicKey[mlkem.CiphertextSize768 : mlkem.CiphertextSize768+X25519KeySize])
	if err != nil {
		return nil, err
	}
	x25519Key, err := x25519SKey.ECDH(peerX25519PKey)
	if err != nil {
		return nil, err
	}
	pfsKey := make([]byte, PfsKeySize) // no more capacity
	copy(pfsKey, mlkem768Key)
	copy(pfsKey[Hash256Length:], x25519Key)
	commonConn.UnitedKey = append(pfsKey, nfsKey...)
	commonConn.AEAD = NewAEAD(pfsPublicKey, commonConn.UnitedKey, commonConn.UseAES)
	commonConn.PeerAEAD = NewAEAD(encryptedPfsPublicKey[:mlkem.CiphertextSize768+X25519KeySize], commonConn.UnitedKey, commonConn.UseAES)

	encryptedTicket := make([]byte, EncryptedTicketLength)
	if _, err := io.ReadFull(conn, encryptedTicket); err != nil {
		return nil, err
	}
	if _, err := commonConn.PeerAEAD.Open(encryptedTicket[:0], nil, encryptedTicket, nil); err != nil {
		return nil, err
	}
	seconds := binary.BigEndian.Uint16(encryptedTicket)

	if c.Seconds > 0 && seconds > 0 {
		c.RWLock.Lock()
		c.Expire = c.timeFunc().Add(time.Duration(seconds) * time.Second)
		c.PfsKey = pfsKey
		c.Ticket = encryptedTicket[:IVLength]
		c.RWLock.Unlock()
	}

	encryptedLength := make([]byte, EncryptedLengthSize)
	if _, err := io.ReadFull(conn, encryptedLength); err != nil {
		return nil, err
	}
	if _, err := commonConn.PeerAEAD.Open(encryptedLength[:0], nil, encryptedLength, nil); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint16(encryptedLength[:2])
	commonConn.PeerPadding = make([]byte, length) // important: allows server sends padding slowly, eliminating 1-RTT's traffic pattern

	if c.XorMode == XorModeRandom {
		commonConn.Conn = NewXorConn(conn, NewCTR(commonConn.UnitedKey, iv), NewCTR(commonConn.UnitedKey, encryptedTicket[:IVLength]), 0, int(length))
	}
	return commonConn, nil
}
