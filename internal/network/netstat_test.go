//go:build windows

package network

import (
	"net"
	"testing"
)

func TestParsePort(t *testing.T) {
	// Exemplo: porta 80 = 0x0050. No Windows dwPort armazena 0x5000 (20480)
	dwPort80 := uint32(0x5000)
	port := parsePort(dwPort80)
	if port != 80 {
		t.Errorf("esperava porta 80, obteve %d", port)
	}

	// Porta 443 = 0x01BB. No Windows dwPort = 0xBB01 (47873)
	dwPort443 := uint32(0xBB01)
	port = parsePort(dwPort443)
	if port != 443 {
		t.Errorf("esperava porta 443, obteve %d", port)
	}
}

func TestIsExternalIP(t *testing.T) {
	tests := []struct {
		ip       string
		external bool
	}{
		{"127.0.0.1", false},
		{"192.168.1.100", false},
		{"10.0.0.1", false},
		{"172.16.0.5", false},
		{"8.8.8.8", true},
		{"1.1.1.1", true},
		{"142.250.190.46", true},
	}

	for _, tc := range tests {
		parsed := net.ParseIP(tc.ip)
		got := isExternalIP(parsed)
		if got != tc.external {
			t.Errorf("isExternalIP(%s) = %v, esperava %v", tc.ip, got, tc.external)
		}
	}
}

func TestGetActiveTcpConnections(t *testing.T) {
	conns, err := GetActiveTcpConnections()
	if err != nil {
		t.Fatalf("GetActiveTcpConnections falhou: %v", err)
	}

	t.Logf("Total de conexões TCP encontradas: %d", len(conns))
	if len(conns) == 0 {
		t.Log("Nenhuma conexão TCP retornada (incomum no Windows)")
	}

	for _, c := range conns {
		if c.ProcessName != "" {
			t.Logf("PID %d (%s) - Local: %s -> Remoto: %s [%s] (Suspeito=%v)",
				c.PID, c.ProcessName, c.LocalAddr, c.RemoteAddr, c.State, c.IsSuspicious)
			break
		}
	}
}
