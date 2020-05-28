package stream

import (
	"crypto/rand"
	"fmt"
	"io"
	"net"

	"github.com/Dreamacro/go-shadowsocks2/shadowstream"
)

type ShadowSocksRStreamCipher struct {
	shadowstream.Cipher
	Key []byte
}

func (ciph *ShadowSocksRStreamCipher) StreamConn(c net.Conn) (net.Conn, error) {
	return NewShadowSocksRStreamConn(c, *ciph)
}

func (ciph *ShadowSocksRStreamCipher) PacketConn(c net.PacketConn) (net.PacketConn, error) {
	return nil, fmt.Errorf("packet conn for ssr not implemented")
}

type ShadowSocksRStreamConn struct {
	net.Conn
	shadowstream.Cipher
	r *shadowstream.Reader
	w *shadowstream.Writer

	// expose iv and key
	ReadIV  []byte
	WriteIV []byte
	Key     []byte
}

func NewShadowSocksRStreamConn(c net.Conn, ciph ShadowSocksRStreamCipher) (*ShadowSocksRStreamConn, error) {
	WriteIV := make([]byte, ciph.IVSize())
	if _, err := rand.Read(WriteIV); err != nil {
		return nil, err
	}

	return &ShadowSocksRStreamConn{
		Conn:    c,
		Cipher:  ciph,
		ReadIV:  nil,
		WriteIV: WriteIV,
		Key:     ciph.Key,
	}, nil
}

func (c *ShadowSocksRStreamConn) initReader() error {
	c.ReadIV = make([]byte, c.IVSize())
	if _, err := io.ReadFull(c.Conn, c.ReadIV); err != nil {
		return err
	}
	c.r = shadowstream.NewReader(c.Conn, c.Decrypter(c.ReadIV))
	return nil
}

func (c *ShadowSocksRStreamConn) Read(b []byte) (int, error) {
	if c.r == nil {
		if err := c.initReader(); err != nil {
			return 0, err
		}
	}
	return c.r.Read(b)
}

func (c *ShadowSocksRStreamConn) initWriter() error {
	_, err := c.Conn.Write(c.WriteIV)
	if err == nil {
		c.w = shadowstream.NewWriter(c.Conn, c.Encrypter(c.WriteIV))
	}
	return err
}

func (c *ShadowSocksRStreamConn) Write(b []byte) (int, error) {
	if c.w == nil {
		if err := c.initWriter(); err != nil {
			return 0, err
		}
	}
	return c.w.Write(b)
}
