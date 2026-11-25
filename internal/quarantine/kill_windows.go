//go:build windows

package quarantine

import (
	"fmt"
	"os/exec"

	"golang.org/x/sys/windows"
)

// TerminateProcessByID finaliza o processo associado ao PID antes da quarentena.
func TerminateProcessByID(pid uint32) error {
	if pid == 0 || pid == 4 {
		return fmt.Errorf("não é permitido encerrar processos protegidos do sistema (PID %d)", pid)
	}

	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, pid)
	if err == nil {
		defer windows.CloseHandle(h)
		if termErr := windows.TerminateProcess(h, 1); termErr == nil {
			return nil
		}
	}

	// Fallback via comando taskkill caso precise forçar encerramento
	cmd := exec.Command("taskkill", "/F", "/PID", fmt.Sprintf("%d", pid))
	return cmd.Run()
}
