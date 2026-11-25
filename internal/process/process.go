package process

// ProcessInfo contém os detalhes de um processo em execução identificado no sistema.
type ProcessInfo struct {
	PID     uint32 `json:"pid"`
	Name    string `json:"name"`
	ExePath string `json:"exe_path"`
	SHA256  string `json:"sha256"`
	Error   string `json:"error,omitempty"`
}
