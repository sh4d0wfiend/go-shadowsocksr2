package util

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/Dreamacro/clash/component/socks5"
	"github.com/ory/dockertest"
	"github.com/sh4d0wfiend/go-shadowsocksr2/encryption"
)

func StartTestServer(enc string) (*dockertest.Pool, *dockertest.Resource) {
	pool, err := dockertest.NewPool("")
	if err != nil {
		log.Fatalf("Could not connect to docker: %s", err)
	}

	resource, err := pool.Run("docker.pkg.github.com/sh4d0wfiend/go-shadowsocksr2/shadowsocksr", "latest", []string{
		fmt.Sprintf("ENCRYPTION=%s", enc),
	})
	if err != nil {
		log.Fatalf("Could not start SSR server: %s", err)
	}

	if err := pool.Retry(func() error {
		log.Printf("Trying to connect at port %s...", resource.GetPort("8388/tcp"))
		c, err := net.DialTimeout("tcp", net.JoinHostPort("", resource.GetPort("8388/tcp")), 1*time.Second)
		if err != nil {
			return err
		}

		c.Close()
		return nil
	}); err != nil {
		log.Fatalf("Could not connect to docker: %s", err)
	}

	return pool, resource
}

func StopTestServer(pool *dockertest.Pool, res *dockertest.Resource) {
	if err := pool.Purge(res); err != nil {
		log.Fatalf("Could not terminate SSR server: %s", err)
	}
}

func serializeAddress(address string) []byte {
	len := uint8(len(address))
	host := []byte(address)
	port := []byte{0, 80}
	buf := [][]byte{{socks5.AtypDomainName, len}, host, port}
	return bytes.Join(buf, nil)
}

func SimulateRequest(enc string) {
	pool, server := StartTestServer(enc)
	defer StopTestServer(pool, server)
	time.Sleep(2 * time.Second)

	var netTransport = &http.Transport{
		Dial: func(network string, addr string) (net.Conn, error) {
			c, err := net.Dial("tcp", net.JoinHostPort("", server.GetPort("8388/tcp")))
			if err != nil {
				log.Fatalf("Failed to connect to proxy: %s", err)
			}

			ciph, err := encryption.PickCipher(enc, nil, "password")
			if err != nil {
				log.Fatalf("Failed to initialize cipher: %s", err)
			}

			ec, err := ciph.StreamConn(c)
			if err != nil {
				log.Fatalf("Failed to initialize encrypted stream: %s", err)
			}

			_, err = ec.Write(serializeAddress("www.baidu.com"))
			if err != nil {
				log.Fatalf("Failed to establish SOCKS connection: %s", err)
			}

			return ec, nil
		},
	}
	var netClient = &http.Client{
		Timeout:   time.Second * 20,
		Transport: netTransport,
	}

	resp, err := netClient.Get("http://www.baidu.com")
	if err != nil {
		log.Fatalf("HTTP request failed: %s", err)
	}
	if resp.StatusCode != 200 {
		log.Fatalf("HTTP request failed with code %d", resp.StatusCode)
	}
}
