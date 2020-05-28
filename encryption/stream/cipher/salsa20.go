package cipher

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"

	"github.com/Dreamacro/go-shadowsocks2/shadowstream"
	"golang.org/x/crypto/salsa20/salsa"
)

type Salsa20Stream struct {
	key *[32]byte
}

func (s *Salsa20Stream) IVSize() int {
	return 8
}

func (s *Salsa20Stream) Encrypter(iv []byte) cipher.Stream {
	if len(iv) != 8 {
		panic(fmt.Errorf("iv size != 8"))
	}
	return &Salsa20StreamCipher{
		nonce: iv,
		key:   *s.key,
	}
}

func (s *Salsa20Stream) Decrypter(iv []byte) cipher.Stream {
	if len(iv) != 8 {
		panic(fmt.Errorf("iv size != 8"))
	}
	return &Salsa20StreamCipher{
		nonce: iv,
		key:   *s.key,
	}
}

type Salsa20StreamCipher struct {
	nonce   []byte
	key     [32]byte
	counter uint64
}

func (s *Salsa20StreamCipher) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic(fmt.Errorf("dst is smaller than src"))
	}
	padLen := int(s.counter % 64)
	buf := make([]byte, len(src)+padLen)

	var subNonce [16]byte
	copy(subNonce[:], s.nonce)
	binary.LittleEndian.PutUint64(subNonce[8:], uint64(s.counter/64))

	// It's difficult to avoid data copy here. src or dst maybe slice from
	// Conn.Read/Write, which can't have padding.
	copy(buf[padLen:], src)
	salsa.XORKeyStream(buf, buf, &subNonce, &s.key)
	copy(dst, buf[padLen:])

	s.counter += uint64(len(src))
}

func Salsa20(key []byte) (shadowstream.Cipher, error) {
	var fixedSizedKey [32]byte
	if len(key) != 32 {
		return nil, shadowstream.KeySizeError(32)
	}

	copy(fixedSizedKey[:], key)
	ciph := Salsa20Stream{
		key: &fixedSizedKey,
	}

	return &ciph, nil
}
