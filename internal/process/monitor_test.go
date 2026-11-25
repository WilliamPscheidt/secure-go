package process

import (
	"os"
	"testing"
)

func TestListRunningProcesses(t *testing.T) {
	procs, err := ListRunningProcesses()
	if err != nil {
		t.Fatalf("falha ao listar processos: %v", err)
	}

	if len(procs) == 0 {
		t.Fatalf("esperava encontrar processos em execução no sistema")
	}

	// Verifica se encontrou pelo menos um processo com PID e hash válido (como o próprio processo de teste)
	myPID := uint32(os.Getpid())
	var foundSelf bool

	for _, p := range procs {
		if p.PID == myPID {
			foundSelf = true
			if p.ExePath == "" {
				t.Errorf("esperava caminho para o próprio processo de teste")
			}
			if p.SHA256 == "" {
				t.Errorf("esperava hash SHA256 para o próprio executável de teste")
			}
			t.Logf("Processo do teste localizado: PID=%d Nome=%s Path=%s Hash=%s", p.PID, p.Name, p.ExePath, p.SHA256)
			break
		}
	}

	if !foundSelf {
		t.Logf("Aviso: processo de teste PID %d não foi listado diretamente no snapshot", myPID)
	}

	t.Logf("Total de processos ativos encontrados: %d", len(procs))
}
