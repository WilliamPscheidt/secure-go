package scheduler

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"secure-go/internal/cache"
	"secure-go/internal/notifier"
	"secure-go/internal/threatintel"
)

func TestSchedulerRunCycle(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_sched.db")

	store, err := cache.NewStore(dbPath)
	if err != nil {
		t.Fatalf("falha ao criar store: %v", err)
	}
	defer store.Close()

	engine := threatintel.NewEngine(store, "")
	notif := notifier.NewNotifier("TestApp")

	sched := NewScheduler(engine, notif, 10*time.Minute)

	var statusMessages []string
	sched.SetCallbacks(
		func(status string) {
			statusMessages = append(statusMessages, status)
		},
		nil,
		nil,
	)

	// Executa um ciclo
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	report := sched.RunCycle(ctx)
	if report == nil {
		t.Fatalf("report não deveria ser nil")
	}

	if report.TotalProcesses == 0 {
		t.Errorf("esperava ter encontrado processos ativos no sistema")
	}

	t.Logf("Ciclo do Scheduler concluído com sucesso: Total=%d, Safe=%d, NewlyChecked=%d, Duração=%v",
		report.TotalProcesses, report.CachedSafe, report.NewlyChecked, report.Duration)
}
