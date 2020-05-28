package mode

import "crypto/cipher"

type OFBStream struct{ cipher.Block }

func (b *OFBStream) IVSize() int                       { return b.BlockSize() }
func (b *OFBStream) Decrypter(iv []byte) cipher.Stream { return cipher.NewOFB(b, iv) }
func (b *OFBStream) Encrypter(iv []byte) cipher.Stream { return cipher.NewOFB(b, iv) }
