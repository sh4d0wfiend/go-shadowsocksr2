package encryption_test

import (
	"testing"

	"github.com/sh4d0wfiend/go-shadowsocksr2/util"
)

func TestRC4MD5(t *testing.T) {
	util.SimulateRequest("rc4-md5")
	util.SimulateRequest("rc4-md5-6")
}

func TestAESCFB(t *testing.T) {
	util.SimulateRequest("aes-128-cfb")
	util.SimulateRequest("aes-192-cfb")
	util.SimulateRequest("aes-256-cfb")
}

func TestAESOFB(t *testing.T) {
	util.SimulateRequest("aes-128-ofb")
	util.SimulateRequest("aes-192-ofb")
	util.SimulateRequest("aes-256-ofb")
}

func TestAESCTR(t *testing.T) {
	util.SimulateRequest("aes-128-ctr")
	util.SimulateRequest("aes-192-ctr")
	util.SimulateRequest("aes-256-ctr")
}

func TestBlowfish(t *testing.T) {
	util.SimulateRequest("bf-cfb")
}

func TestCast5(t *testing.T) {
	util.SimulateRequest("cast5-cfb")
}

func TestDES(t *testing.T) {
	util.SimulateRequest("des-cfb")
}

func TestSalsa20(t *testing.T) {
	util.SimulateRequest("salsa20")
}

func TestChacha20(t *testing.T) {
	util.SimulateRequest("chacha20-ietf")
}
