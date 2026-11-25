//go:build windows

package network

import (
	"fmt"
	"net"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"secure-go/internal/process"
)

var (
	modIphlpapi             = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable = modIphlpapi.NewProc("GetExtendedTcpTable")
)

const (
	AF_INET                 = 2
	TCP_TABLE_OWNER_PID_ALL = 5
	ERROR_INSUFFICIENT_BUFFER = 122
)

type mibTcpRowOwnerPid struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPid  uint32
}

var tcpStateMap = map[uint32]string{
	1:  "CLOSED",
	2:  "LISTEN",
	3:  "SYN_SENT",
	4:  "SYN_RCVD",
	5:  "ESTABLISHED",
	6:  "FIN_WAIT1",
	7:  "FIN_WAIT2",
	8:  "CLOSE_WAIT",
	9:  "CLOSING",
	10: "LAST_ACK",
	11: "TIME_WAIT",
	12: "DELETE_TCB",
}

var knownSuspiciousPorts = map[int]string{
	4444:  "Porta padrão Metasploit / Reverse Shell",
	50050: "Porta padrão Cobalt Strike TeamServer",
	1337:  "Porta hacker comum (BackOrifice / Elite)",
	31337: "Porta BackOrifice Trojan",
	6667:  "Porta IRC (comum em redes Botnets)",
	9001:  "Porta Tor Relay / SOCKS",
	9050:  "Porta Tor Proxy SOCKS",
	3333:  "Porta Stratum / Mineração de Criptomoedas",
	14444: "Porta Mineração Monero / XMRig",
	8888:  "Porta alternativa C2 / Proxy",
	9999:  "Porta Reverse Shell",
	5555:  "Porta ADB / Trojan de Acesso Remoto",
}

var lolbins = map[string]bool{
	"powershell.exe": true,
	"pwsh.exe":       true,
	"cmd.exe":        true,
	"rundll32.exe":   true,
	"regsvr32.exe":   true,
	"mshta.exe":      true,
	"certutil.exe":   true,
	"wscript.exe":    true,
	"cscript.exe":    true,
	"bitsadmin.exe":  true,
}

// ConnectionEntry representa uma conexão TCP ativa associada a um processo do sistema.
type ConnectionEntry struct {
	PID             uint32 `json:"pid"`
	ProcessName     string `json:"process_name"`
	ExePath         string `json:"exe_path"`
	LocalAddr       string `json:"local_addr"`
	LocalIP         string `json:"local_ip"`
	LocalPort       int    `json:"local_port"`
	RemoteAddr      string `json:"remote_addr"`
	RemoteIP        string `json:"remote_ip"`
	RemotePort      int    `json:"remote_port"`
	State           string `json:"state"`
	IsSuspicious    bool   `json:"is_suspicious"`
	RiskLevel       string `json:"risk_level"`       // "NORMAL", "SUSPICIOUS", "CRITICAL"
	ThreatIndicator string `json:"threat_indicator"` // Explicação do risco identificado
}

// parsePort decodifica a porta armazenada em network byte order pela API do Windows.
func parsePort(dwPort uint32) int {
	return int(((dwPort & 0xFF) << 8) | ((dwPort >> 8) & 0xFF))
}

// parseIPv4 converte o DWORD de endereço para IP no formato padrão.
func parseIPv4(dwAddr uint32) net.IP {
	return net.IPv4(
		byte(dwAddr),
		byte(dwAddr>>8),
		byte(dwAddr>>16),
		byte(dwAddr>>24),
	)
}

// isExternalIP retorna true se o IP não for loopback e não for endereço de rede privada.
func isExternalIP(ip net.IP) bool {
	if ip == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() {
		return false
	}
	return !ip.IsPrivate()
}

// GetProcessMap retorna um mapa rápido de PID -> Nome de Processo.
func GetProcessMap() map[uint32]string {
	procMap := make(map[uint32]string)
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return procMap
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	if err := windows.Process32First(snapshot, &entry); err != nil {
		return procMap
	}

	for {
		name := syscall.UTF16ToString(entry.ExeFile[:])
		procMap[entry.ProcessID] = name
		if err := windows.Process32Next(snapshot, &entry); err != nil {
			break
		}
	}
	return procMap
}

// GetActiveTcpConnections enumera todas as conexões TCP ativas e mapeia para os PIDs e processos correspondentes.
func GetActiveTcpConnections() ([]ConnectionEntry, error) {
	var size uint32
	// Primeira chamada para descobrir o tamanho necessário do buffer
	procGetExtendedTcpTable.Call(
		0,
		uintptr(unsafe.Pointer(&size)),
		1, // bOrder = TRUE
		AF_INET,
		TCP_TABLE_OWNER_PID_ALL,
		0,
	)

	if size == 0 {
		return nil, fmt.Errorf("falha ao determinar tamanho da tabela TCP")
	}

	buf := make([]byte, size)
	r1, _, _ := procGetExtendedTcpTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		1,
		AF_INET,
		TCP_TABLE_OWNER_PID_ALL,
		0,
	)

	if r1 != 0 {
		return nil, fmt.Errorf("GetExtendedTcpTable falhou com código: %d", r1)
	}

	numEntries := *(*uint32)(unsafe.Pointer(&buf[0]))
	if numEntries == 0 {
		return []ConnectionEntry{}, nil
	}

	// Obtém mapa rápido de nomes de processos
	procMap := GetProcessMap()

	rowSize := unsafe.Sizeof(mibTcpRowOwnerPid{})
	rowsPtr := uintptr(unsafe.Pointer(&buf[4]))

	var entries []ConnectionEntry

	for i := uint32(0); i < numEntries; i++ {
		row := (*mibTcpRowOwnerPid)(unsafe.Pointer(rowsPtr + uintptr(i)*rowSize))

		localIP := parseIPv4(row.LocalAddr)
		localPort := parsePort(row.LocalPort)
		remoteIP := parseIPv4(row.RemoteAddr)
		remotePort := parsePort(row.RemotePort)

		stateStr, found := tcpStateMap[row.State]
		if !found {
			stateStr = fmt.Sprintf("UNKNOWN (%d)", row.State)
		}

		procName := procMap[row.OwningPid]
		if procName == "" {
			if row.OwningPid == 0 {
				procName = "System Idle"
			} else if row.OwningPid == 4 {
				procName = "System Kernel"
			} else {
				procName = fmt.Sprintf("PID %d", row.OwningPid)
			}
		}

		lowerProc := strings.ToLower(procName)
		isSuspicious := false
		riskLevel := "NORMAL"
		var indicators []string

		// 1. Checa portas comumente associadas a malware / C2 / RAT
		if desc, isSus := knownSuspiciousPorts[remotePort]; isSus {
			isSuspicious = true
			riskLevel = "CRITICAL"
			indicators = append(indicators, fmt.Sprintf("Alerta: Porta remota %d (%s)", remotePort, desc))
		}
		if desc, isSus := knownSuspiciousPorts[localPort]; isSus && stateStr == "LISTEN" {
			isSuspicious = true
			riskLevel = "CRITICAL"
			indicators = append(indicators, fmt.Sprintf("Alerta: Escutando na porta suspeita %d (%s)", localPort, desc))
		}

		// 2. Checa LOLBins (ferramentas de sistema) conectando a IPs externos da Internet
		isExt := isExternalIP(remoteIP)
		if isExt && lolbins[lowerProc] && (stateStr == "ESTABLISHED" || stateStr == "SYN_SENT") {
			isSuspicious = true
			riskLevel = "CRITICAL"
			indicators = append(indicators, fmt.Sprintf("LOLBin (%s) conectado a IP externo público (%s)", procName, remoteIP.String()))
		}

		entry := ConnectionEntry{
			PID:             row.OwningPid,
			ProcessName:     procName,
			LocalAddr:       fmt.Sprintf("%s:%d", localIP.String(), localPort),
			LocalIP:         localIP.String(),
			LocalPort:       localPort,
			RemoteAddr:      fmt.Sprintf("%s:%d", remoteIP.String(), remotePort),
			RemoteIP:        remoteIP.String(),
			RemotePort:      remotePort,
			State:           stateStr,
			IsSuspicious:    isSuspicious,
			RiskLevel:       riskLevel,
			ThreatIndicator: strings.Join(indicators, " | "),
		}

		// Tenta preencher caminho completo para processos suspeitos ou se requisitado
		if isSuspicious {
			if path, err := process.GetProcessExePath(row.OwningPid); err == nil {
				entry.ExePath = path
			}
		}

		entries = append(entries, entry)
	}

	return entries, nil
}
