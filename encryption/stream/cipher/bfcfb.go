package cipher

import (
	"github.com/Dreamacro/go-shadowsocks2/shadowstream"
	"github.com/sh4d0wfiend/go-shadowsocksr2/encryption/stream/mode"
	"golang.org/x/crypto/blowfish"
)

func BFCFB(key []byte) (shadowstream.Cipher, error) {
	blk, err := blowfish.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &mode.CFBStream{blk}, nil
}
