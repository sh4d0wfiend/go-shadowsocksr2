package cipher

import (
	"crypto/aes"

	"github.com/Dreamacro/go-shadowsocks2/shadowstream"
	"github.com/sh4d0wfiend/go-shadowsocksr2/encryption/stream/mode"
)

func AESOFB(key []byte) (shadowstream.Cipher, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &mode.OFBStream{blk}, nil
}
