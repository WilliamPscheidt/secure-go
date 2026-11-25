//go:build windows

package process

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"secure-go/internal/hasher"
)

var (
	modkernel32                   = windows.NewLazySystemDLL("kernel32.dll")
	procQueryFullProcessImageName = modkernel32.NewProc("QueryFullProcessImageNameW")
)

// queryFullProcessImageName chama a API do Win32 para obter o caminho completo do executável.
func queryFullProcessImageName(hProcess windows.Handle, flags uint32) (string, error) {
	var buf [syscall.MAX_PATH * 2]uint16
	size := uint32(len(buf))

	r1, _, err := procQueryFullProcessImageName.Call(
		uintptr(hProcess),
		uintptr(flags),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	if r1 == 0 {
		return "", err
	}
	return syscall.UTF16ToString(buf[:size]), nil
}

// GetProcessExePath tenta obter o caminho absoluto do executável dado o PID.
func GetProcessExePath(pid uint32) (string, error) {
	if pid == 0 {
		return "[System Idle Process]", nil
	}
	if pid == 4 {
		return "[System Kernel]", nil
	}

	// Tenta abrir com PROCESS_QUERY_LIMITED_INFORMATION (compatível com Windows Vista+)
	hProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		// Tenta fallback com PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
		hProcess, err = windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, pid)
		if err != nil {
			return "", fmt.Errorf("permissão negada (OpenProcess): %w", err)
		}
	}
	defer windows.CloseHandle(hProcess)

	path, err := queryFullProcessImageName(hProcess, 0)
	if err != nil {
		return "", fmt.Errorf("falha ao consultar caminho: %w", err)
	}

	return path, nil
}

// ListRunningProcesses faz o snapshot de todos os processos ativos e calcula os hashes dos executáveis.
func ListRunningProcesses() ([]ProcessInfo, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar snapshot de processos: %w", err)
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	if err := windows.Process32First(snapshot, &entry); err != nil {
		return nil, fmt.Errorf("falha ao iterar primeiro processo: %w", err)
	}

	// Cache de hash em memória por caminho de arquivo durante a listagem
	// (evita recalcular o hash de 20 instâncias do Chrome.exe no mesmo snapshot)
	pathHashCache := make(map[string]string)

	var processes []ProcessInfo

	for {
		pid := entry.ProcessID
		name := syscall.UTF16ToString(entry.ExeFile[:])

		pInfo := ProcessInfo{
			PID:  pid,
			Name: name,
		}

		exePath, err := GetProcessExePath(pid)
		if err != nil {
			pInfo.Error = err.Error()
		} else {
			pInfo.ExePath = exePath

			// Se for um arquivo físico existente no disco, calcula ou reaproveita o SHA-256
			if exePath != "" && exePath[0] != '[' {
				if cachedHash, ok := pathHashCache[exePath]; ok {
					pInfo.SHA256 = cachedHash
				} else {
					// Verifica se arquivo existe
					if _, statErr := os.Stat(exePath); statErr == nil {
						hash, hashErr := hasher.ComputeFileSHA256(exePath)
						if hashErr != nil {
							pInfo.Error = fmt.Sprintf("erro de hash: %v", hashErr)
						} else {
							pInfo.SHA256 = hash
							pathHashCache[exePath] = hash
						}
					} else {
						// Pode ser um path em formato de dispositivo NT (\Device\HarddiskVolume...)
						cleanPath := filepath.Clean(exePath)
						hash, hashErr := hasher.ComputeFileSHA256(cleanPath)
						if hashErr == nil {
							pInfo.SHA256 = hash
							pathHashCache[exePath] = hash
						}
					}
				}
			}
		}

		processes = append(processes, pInfo)

		if err := windows.Process32Next(snapshot, &entry); err != nil {
			break
		}
	}

	return processes, nil
}
