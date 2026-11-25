//go:build !windows

package quarantine

import (
	"fmt"
	"os"
)

// TerminateProcessByID emula finalização em sistemas não-Windows.
func TerminateProcessByID(pid uint32) error {
	p, err := os.FindProcess(int(pid))
	if err != nil {
		return err
	}
	return p.Kill()
}
