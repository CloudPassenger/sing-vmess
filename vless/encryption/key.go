package encryption

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/base64"
	"runtime"

	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/cpu"
	"lukechampine.com/blake3"
)

const (
	X25519KeySize = 32
)

var (
	// Keep in sync with crypto/internal/fips140/aes/gcm.supportsAESGCM.
	hasGCMAsmAMD64 = cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ && cpu.X86.HasSSE41 && cpu.X86.HasSSSE3
	hasGCMAsmARM64 = cpu.ARM64.HasAES && cpu.ARM64.HasPMULL
	hasGCMAsmS390X = cpu.S390X.HasAES && cpu.S390X.HasAESCTR && cpu.S390X.HasGHASH
	hasGCMAsmPPC64 = runtime.GOARCH == "ppc64" || runtime.GOARCH == "ppc64le"

	hasAESGCMHardwareSupport = hasGCMAsmAMD64 || hasGCMAsmARM64 || hasGCMAsmS390X || hasGCMAsmPPC64
)

func GenMLKEM768(seedStr string) (seedBase64, clientBase64, hash32Base64 string, err error) {
	var seed [mlkem.SeedSize]byte
	if len(seedStr) > 0 {
		s, _ := base64.RawURLEncoding.DecodeString(seedStr)
		if len(s) != mlkem.EncapsulationKeySize768 {
			err = E.New("invalid length of ML-KEM-768 seed: ", seedStr)
			return
		}
		seed = [mlkem.SeedSize]byte(s)
	} else {
		_, _ = rand.Read(seed[:])
	}

	key, _ := mlkem.NewDecapsulationKey768(seed[:])
	client := key.EncapsulationKey().Bytes()
	hash32 := blake3.Sum256(client)
	seedBase64 = base64.RawURLEncoding.EncodeToString(seed[:])
	clientBase64 = base64.RawURLEncoding.EncodeToString(client)
	hash32Base64 = base64.RawURLEncoding.EncodeToString(hash32[:])
	return
}

func GenX25519(privateKeyStr string) (privateKeyBase64, passwordBase64, hash32Base64 string, err error) {
	var privateKey [X25519KeySize]byte
	if len(privateKeyStr) > 0 {
		s, _ := base64.RawURLEncoding.DecodeString(privateKeyStr)
		if len(s) != X25519KeySize {
			err = E.New("invalid length of X25519 private key: ", privateKeyStr)
			return
		}
		privateKey = [X25519KeySize]byte(s)
	} else {
		_, _ = rand.Read(privateKey[:])
	}

	// Avoid generating equivalent X25519 private keys
	// https://github.com/XTLS/Xray-core/pull/1747
	//
	// Modify random bytes using algorithm described at:
	// https://cr.yp.to/ecdh.html.
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	key, err := ecdh.X25519().NewPrivateKey(privateKey[:])
	if err != nil {
		return
	}
	password := key.PublicKey().Bytes()
	hash32 := blake3.Sum256(password)
	privateKeyBase64 = base64.RawURLEncoding.EncodeToString(privateKey[:])
	passwordBase64 = base64.RawURLEncoding.EncodeToString(password)
	hash32Base64 = base64.RawURLEncoding.EncodeToString(hash32[:])
	return
}
