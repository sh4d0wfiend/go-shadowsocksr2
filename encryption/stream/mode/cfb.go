package mode

import "crypto/cipher"

type CFBStream struct{ cipher.Block }

func (b *CFBStream) IVSize() int                       { return b.BlockSize() }
func (b *CFBStream) Decrypter(iv []byte) cipher.Stream { return cipher.NewCFBDecrypter(b, iv) }
func (b *CFBStream) Encrypter(iv []byte) cipher.Stream { return cipher.NewCFBEncrypter(b, iv) }
