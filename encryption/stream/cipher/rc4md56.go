package cipher

import (
	"crypto/cipher"
	"crypto/md5"
	"crypto/rc4"

	"github.com/Dreamacro/go-shadowsocks2/shadowstream"
)

type RC4MD56Key []byte

func (k RC4MD56Key) IVSize() int {
	return 6
}

func (k RC4MD56Key) Encrypter(iv []byte) cipher.Stream {
	h := md5.New()
	h.Write([]byte(k))
	h.Write(iv)
	rc4key := h.Sum(nil)
	c, _ := rc4.NewCipher(rc4key)
	return c
}

func (k RC4MD56Key) Decrypter(iv []byte) cipher.Stream {
	return k.Encrypter(iv)
}

func RC4MD56(key []byte) (shadowstream.Cipher, error) {
	return RC4MD56Key(key), nil
}
