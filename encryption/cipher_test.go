package encryption_test

import (
	"testing"

	"github.com/sh4d0wfiend/go-shadowsocksr2/encryption"
	"github.com/sh4d0wfiend/go-shadowsocksr2/util"
)

func TestRC4MD5(t *testing.T) {
	if err := util.SimulateRequest("rc4-md5"); err != nil {
		t.Fatalf("RC4-MD5 cipher failed: %s", err)
	}
	if err := util.SimulateRequest("rc4-md5-6"); err != nil {
		t.Fatalf("RC4-MD5-6 cipher failed: %s", err)
	}
}

func TestAESCFB(t *testing.T) {
	if err := util.SimulateRequest("aes-128-cfb"); err != nil {
		t.Fatalf("AES-128-CFB cipher failed: %s", err)
	}
	if err := util.SimulateRequest("aes-192-cfb"); err != nil {
		t.Fatalf("AES-192-CFB cipher failed: %s", err)
	}
	if err := util.SimulateRequest("aes-256-cfb"); err != nil {
		t.Fatalf("AES-256-CFB cipher failed: %s", err)
	}
}

func TestAESOFB(t *testing.T) {
	if err := util.SimulateRequest("aes-128-ofb"); err != nil {
		t.Fatalf("AES-128-OFB cipher failed: %s", err)
	}
	if err := util.SimulateRequest("aes-192-ofb"); err != nil {
		t.Fatalf("AES-192-OFB cipher failed: %s", err)
	}
	if err := util.SimulateRequest("aes-256-ofb"); err != nil {
		t.Fatalf("AES-256-OFB cipher failed: %s", err)
	}
}

func TestAESCTR(t *testing.T) {
	if err := util.SimulateRequest("aes-128-ctr"); err != nil {
		t.Fatalf("AES-128-CTR cipher failed: %s", err)
	}
	if err := util.SimulateRequest("aes-192-ctr"); err != nil {
		t.Fatalf("AES-192-CTR cipher failed: %s", err)
	}
	if err := util.SimulateRequest("aes-256-ctr"); err != nil {
		t.Fatalf("AES-256-CTR cipher failed: %s", err)
	}
}

func TestBlowfish(t *testing.T) {
	if err := util.SimulateRequest("bf-cfb"); err != nil {
		t.Fatalf("BF-CFB cipher failed: %s", err)
	}
}

func TestCast5(t *testing.T) {
	if err := util.SimulateRequest("cast5-cfb"); err != nil {
		t.Fatalf("Cast5-CFB cipher failed: %s", err)
	}
}

func TestDES(t *testing.T) {
	if err := util.SimulateRequest("des-cfb"); err != nil {
		t.Fatalf("DES-CFB cipher failed: %s", err)
	}
}

func TestSalsa20(t *testing.T) {
	if err := util.SimulateRequest("salsa20"); err != nil {
		t.Fatalf("Salsa20 cipher failed: %s", err)
	}
}

func TestChacha20(t *testing.T) {
	if err := util.SimulateRequest("chacha20-ietf"); err != nil {
		t.Fatalf("Chacha20-IETF cipher failed: %s", err)
	}
}

func TestKeySize(t *testing.T) {
	if _, err := encryption.PickCipher("aes-256-cfb", make([]byte, 32), "test"); err != nil {
		t.Fatalf("PickCipher should not error on correct iv size")
	}

	if _, err := encryption.PickCipher("aes-256-cfb", make([]byte, 16), "test"); err == nil {
		t.Fatalf("PickCipher should error on correct iv size")
	}
}
