package encryption

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/crypto/chacha20poly1305"
	"lukechampine.com/blake3"
)

const (
	// Magic header bytes (TLS 1.3 disguise)
	MagicHeaderByte0 = 23
	MagicHeaderByte1 = 3
	MagicHeaderByte2 = 3

	// Protocol field lengths
	HeaderLength        = 5     // Magic header length
	IVLength            = 16    // Initialization Vector length
	NonceLength         = 12    // AEAD nonce length
	AEADTagLength       = 16    // AEAD authentication tag length
	Hash256Length       = 32    // BLAKE3 hash length
	EncryptedLengthSize = 18    // 2-byte length + 16-byte tag
	XrayBufferSize      = 8192  // Xray buffer size
	MinPacketLength     = 17    // Minimum packet length (1 byte data + 16 byte tag)
	MaxPacketLength     = 17000 // Maximum packet length
	MinPaddingLength    = 35    // Minimum first padding length (18+17)
	MaxTotalPadding     = 65553 // Maximum total padding length (18+65535)

	Challenge = "VLESS"
)

var (
	_ N.ReaderWithUpstream = (*CommonConn)(nil)
	_ N.WriterWithUpstream = (*CommonConn)(nil)
)

type CommonConn struct {
	net.Conn
	UseAES      bool
	Client      *Client
	UnitedKey   []byte
	PreWrite    []byte
	AEAD        *AEAD
	PeerAEAD    *AEAD
	PeerPadding []byte
	rawInput    bytes.Buffer // PeerInBytes
	input       bytes.Reader // PeerCache
}

func NewCommonConn(conn net.Conn, useAES bool) *CommonConn {
	return &CommonConn{
		Conn:   conn,
		UseAES: useAES,
	}
}

func (c *CommonConn) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	outBytes := buf.Get(HeaderLength + XrayBufferSize + AEADTagLength)
	defer buf.Put(outBytes)
	for n := 0; n < len(b); {
		b := b[n:]
		if len(b) > XrayBufferSize {
			b = b[:XrayBufferSize] // for avoiding another copy() in peer's Read()
		}
		n += len(b)
		headerAndData := outBytes[:HeaderLength+len(b)+AEADTagLength]
		EncodeHeader(headerAndData, len(b)+AEADTagLength)
		nonceGotMax := false
		if bytes.Equal(c.AEAD.Nonce[:], MaxNonce) {
			nonceGotMax = true
		}
		c.AEAD.Seal(headerAndData[:HeaderLength], nil, b, headerAndData[:HeaderLength])
		if nonceGotMax {
			c.AEAD = NewAEAD(headerAndData, c.UnitedKey, c.UseAES)
		}
		if c.PreWrite != nil {
			headerAndData = append(c.PreWrite, headerAndData...)
			c.PreWrite = nil
		}
		if _, err := c.Conn.Write(headerAndData); err != nil {
			return 0, err
		}
	}
	return len(b), nil
}

func (c *CommonConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	if c.PeerAEAD == nil { // client's 0-RTT
		serverRandom := make([]byte, IVLength)
		if _, err := io.ReadFull(c.Conn, serverRandom); err != nil {
			return 0, err
		}
		c.PeerAEAD = NewAEAD(serverRandom, c.UnitedKey, c.UseAES)
		if xorConn, isXorConn := c.Conn.(*XorConn); isXorConn {
			xorConn.PeerCTR = NewCTR(c.UnitedKey, serverRandom)
		}
	}
	if c.PeerPadding != nil { // client's 1-RTT
		if _, err := io.ReadFull(c.Conn, c.PeerPadding); err != nil {
			return 0, err
		}
		if _, err := c.PeerAEAD.Open(c.PeerPadding[:0], nil, c.PeerPadding, nil); err != nil {
			return 0, err
		}
		c.PeerPadding = nil
	}
	if c.input.Len() > 0 {
		return c.input.Read(b)
	}
	peerHeader := [HeaderLength]byte{}
	if _, err := io.ReadFull(c.Conn, peerHeader[:]); err != nil {
		return 0, err
	}
	l, err := DecodeHeader(peerHeader[:]) // l: 17~17000
	if err != nil {
		if c.Client != nil && E.IsMulti(err, ErrInvalidHeader) { // client's 0-RTT
			c.Client.RWLock.Lock()
			if bytes.HasPrefix(c.UnitedKey, c.Client.PfsKey) {
				c.Client.Expire = time.Now() // expired
			}
			c.Client.RWLock.Unlock()
			return 0, E.New("new handshake needed")
		}
		return 0, err
	}
	c.Client = nil
	if c.rawInput.Cap() < l {
		c.rawInput.Grow(l) // no need to use sync.Pool, because we are always reading
	}
	peerData := c.rawInput.Bytes()[:l]
	if _, err := io.ReadFull(c.Conn, peerData); err != nil {
		return 0, err
	}
	dst := peerData[:l-AEADTagLength]
	if len(dst) <= len(b) {
		dst = b[:len(dst)] // avoids another copy()
	}
	var newAEAD *AEAD
	if bytes.Equal(c.PeerAEAD.Nonce[:], MaxNonce) {
		newAEAD = NewAEAD(append(peerHeader[:], peerData...), c.UnitedKey, c.UseAES)
	}
	_, err = c.PeerAEAD.Open(dst[:0], nil, peerData, peerHeader[:])
	if newAEAD != nil {
		c.PeerAEAD = newAEAD
	}
	if err != nil {
		return 0, err
	}
	if len(dst) > len(b) {
		c.input.Reset(dst[copy(b, dst):])
		dst = b // for len(dst)
	}
	return len(dst), nil
}

func (c *CommonConn) WriterReplaceable() bool {
	return false
}

func (c *CommonConn) ReaderReplaceable() bool {
	return false
}

func (c *CommonConn) Upstream() any {
	return c.Conn
}

type AEAD struct {
	cipher.AEAD
	Nonce [NonceLength]byte
}

func NewAEAD(ctx, key []byte, useAES bool) *AEAD {
	subkey := make([]byte, 32)
	blake3.DeriveKey(subkey, string(ctx), key)
	var aead cipher.AEAD
	if useAES {
		block, _ := aes.NewCipher(subkey)
		aead, _ = cipher.NewGCM(block)
	} else {
		aead, _ = chacha20poly1305.New(subkey)
	}
	return &AEAD{AEAD: aead}
}

func (a *AEAD) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if nonce == nil {
		nonce = IncreaseNonce(a.Nonce[:])
	}
	return a.AEAD.Seal(dst, nonce, plaintext, additionalData)
}

func (a *AEAD) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if nonce == nil {
		nonce = IncreaseNonce(a.Nonce[:])
	}
	return a.AEAD.Open(dst, nonce, ciphertext, additionalData)
}

func IncreaseNonce(nonce []byte) []byte {
	for i := 0; i < NonceLength; i++ {
		nonce[NonceLength-1-i]++
		if nonce[NonceLength-1-i] != 0 {
			break
		}
	}
	return nonce
}

var MaxNonce = bytes.Repeat([]byte{0xFF}, NonceLength)

func EncodeHeader(header []byte, length int) {
	header[0] = MagicHeaderByte0
	header[1] = MagicHeaderByte1
	header[2] = MagicHeaderByte2
	binary.BigEndian.PutUint16(header[3:], uint16(length))
}

var ErrInvalidHeader = E.New("invalid header")

func DecodeHeader(header []byte) (length int, err error) {
	length = int(binary.BigEndian.Uint16(header[3:]))
	if header[0] != MagicHeaderByte0 || header[1] != MagicHeaderByte1 || header[2] != MagicHeaderByte2 {
		length = 0
	}
	if length < MinPacketLength || length > MaxPacketLength { // TODO: TLSv1.3 max length
		err = E.Extend(ErrInvalidHeader, fmt.Sprint(header[:HeaderLength])) // DO NOT CHANGE: relied by client's Read()
	}
	return
}

func ParsePadding(padding []string, paddingLens, paddingGaps *[][3]int) (err error) {
	if len(padding) == 0 {
		return
	}
	maxLen := 0
	for i, segment := range padding {
		parts := strings.Split(segment, "-")
		if len(parts) < 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
			return E.New("invalid padding length/gap parameter: " + segment)
		}
		parsedValues := [3]int{}
		if parsedValues[0], err = strconv.Atoi(parts[0]); err != nil {
			return
		}
		if parsedValues[1], err = strconv.Atoi(parts[1]); err != nil {
			return
		}
		if parsedValues[2], err = strconv.Atoi(parts[2]); err != nil {
			return
		}
		if i == 0 && (parsedValues[0] < 100 || parsedValues[1] < MinPaddingLength || parsedValues[2] < MinPaddingLength) {
			return E.New("first padding length must not be smaller than 35")
		}
		if i%2 == 0 {
			*paddingLens = append(*paddingLens, parsedValues)
			maxLen += max(parsedValues[1], parsedValues[2])
		} else {
			*paddingGaps = append(*paddingGaps, parsedValues)
		}
	}
	if maxLen > MaxTotalPadding {
		return E.New("total padding length must not be larger than 65553")
	}
	return
}

func CreatePadding(paddingLens, paddingGaps [][3]int) (length int, lens []int, gaps []time.Duration) {
	if len(paddingLens) == 0 {
		paddingLens = [][3]int{{100, 111, 1111}, {50, 0, 3333}}
		paddingGaps = [][3]int{{75, 0, 111}}
	}
	for _, y := range paddingLens {
		l := 0
		if y[0] >= int(randBetween(0, 100)) {
			l = int(randBetween(int64(y[1]), int64(y[2])))
		}
		lens = append(lens, l)
		length += l
	}
	for _, y := range paddingGaps {
		g := 0
		if y[0] >= int(randBetween(0, 100)) {
			g = int(randBetween(int64(y[1]), int64(y[2])))
		}
		gaps = append(gaps, time.Duration(g)*time.Millisecond)
	}
	return
}

func randBetween(from, to int64) int64 {
	if from == to {
		return from
	}
	if to < from {
		from, to = to, from
	}
	return from + rand.Int64N(to-from)
}
