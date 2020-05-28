package cipher

import (
	"crypto/des"

	"github.com/Dreamacro/go-shadowsocks2/shadowstream"
	"github.com/sh4d0wfiend/go-shadowsocksr2/encryption/stream/mode"
)

func DESCFB(key []byte) (shadowstream.Cipher, error) {
	blk, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &mode.CFBStream{blk}, nil
}
