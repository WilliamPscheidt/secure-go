package ui

import (
	"image/color"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"
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
