package ui

import (
	"image/color"
	"path/filepath"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"secure-go/internal/cache"
	"secure-go/internal/quarantine"
	"secure-go/internal/threatintel"
)

func TestComponentsCreation(t *testing.T) {
	_ = test.NewApp()

	pill := NewPillBadge("TESTE", color.White, ColorBluePrimary)
	if pill == nil {
		t.Fatal("NewPillBadge retornou nil")
	}

	lbl := widget.NewLabel("100")
	card := NewMetricCard("TITULO", "Subtitulo", lbl, "OK", ColorCyan, ColorCyanAlpha)
	if card == nil {
		t.Fatal("NewMetricCard retornou nil")
	}

	secCard := NewSecurityRowCard(IconFAShield, "Scanner", "Subtitulo", widget.NewButton("Scan", nil), nil)
	if secCard == nil {
		t.Fatal("NewSecurityRowCard retornou nil")
	}

	gauge := NewProtectionScoreGauge(100, "Excelente")
	if gauge == nil {
		t.Fatal("NewProtectionScoreGauge retornou nil")
	}

	panel := NewPanelCard("PAINEL", nil, widget.NewLabel("Conteúdo"))
	if panel == nil {
		t.Fatal("NewPanelCard retornou nil")
	}
}

func TestCanvasArc(t *testing.T) {
	_ = test.NewApp()

	arc := canvas.NewArc(180, 360, 0.85, ColorEmerald)
	if arc == nil {
		t.Fatal("canvas.NewArc retornou nil")
	}
	arc.Resize(fyne.NewSize(160, 160))
}

func TestCustomThemeFont(t *testing.T) {
	_ = test.NewApp()

	th := NewCustomTheme()
	regularFont := th.Font(fyne.TextStyle{})
	if regularFont == nil {
		t.Error("esperava fonte regular válida")
	} else {
		t.Logf("Fonte Regular carregada: %s (tamanho=%d bytes)", regularFont.Name(), len(regularFont.Content()))
	}

	boldFont := th.Font(fyne.TextStyle{Bold: true})
	if boldFont == nil {
		t.Error("esperava fonte bold válida")
	} else {
		t.Logf("Fonte Bold carregada: %s (tamanho=%d bytes)", boldFont.Name(), len(boldFont.Content()))
	}

	monoFont := th.Font(fyne.TextStyle{Monospace: true})
	if monoFont == nil {
		t.Error("esperava fonte mono válida")
	} else {
		t.Logf("Fonte Mono carregada: %s (tamanho=%d bytes)", monoFont.Name(), len(monoFont.Content()))
	}
}

func TestQuarantineTabCreation(t *testing.T) {
	app := test.NewApp()
	w := app.NewWindow("Test")

	tempDir := t.TempDir()
	vaultDir := filepath.Join(tempDir, "vault")
	v, err := quarantine.NewVault(vaultDir)
	if err != nil {
		t.Fatalf("falha ao criar cofre de teste: %v", err)
	}

	dbPath := filepath.Join(tempDir, "test.db")
	store, _ := cache.NewStore(dbPath)
	defer store.Close()
	engine := threatintel.NewEngine(store, "")

	tab := NewQuarantineTab(w, v, engine)
	if tab == nil {
		t.Fatal("NewQuarantineTab retornou nil")
	}

	content := tab.Content()
	if content == nil {
		t.Fatal("tab.Content retornou nil")
	}
}
