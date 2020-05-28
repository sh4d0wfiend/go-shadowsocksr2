package util_test

import (
	"testing"

	"github.com/sh4d0wfiend/go-shadowsocksr2/util"
)

func TestSimulateRequest(t *testing.T) {
	if err := util.SimulateRequest("none"); err != nil {
		t.Fatalf("Failed to simulate request: %s", err)
	}
}
