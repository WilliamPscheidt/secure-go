//go:build !windows

package process

import "errors"

func ListRunningProcesses() ([]ProcessInfo, error) {
	return nil, errors.New("monitor de processos disponível apenas em ambiente Windows")
}

func GetProcessExePath(pid uint32) (string, error) {
	return "", errors.New("não implementado para este sistema operacional")
}
