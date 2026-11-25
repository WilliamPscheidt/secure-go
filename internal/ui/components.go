package ui

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

// NewPillBadge cria uma etiqueta arredondada no estilo "pill" moderno.
func NewPillBadge(text string, textColor, bgColor color.Color) fyne.CanvasObject {
	bg := canvas.NewRectangle(bgColor)
	bg.CornerRadius = 12
	bg.StrokeColor = textColor
	bg.StrokeWidth = 0.5

	lbl := canvas.NewText(text, textColor)
	lbl.TextStyle = fyne.TextStyle{Bold: true}
	lbl.TextSize = 11

	content := container.NewCenter(lbl)
	return container.NewStack(bg, container.NewPadded(content))
}

// NewMetricCard cria um cartão moderno com fundo elevado, borda sutil, métrica grande e badge.
func NewMetricCard(title, subtitle string, valueLabel *widget.Label, badgeText string, badgeTextCol, badgeBgCol color.Color) fyne.CanvasObject {
	bg := canvas.NewRectangle(ColorCardBg)
	bg.CornerRadius = 10
	bg.StrokeColor = ColorCardBorder
	bg.StrokeWidth = 1.0

	titleLabel := canvas.NewText(title, ColorTextSecondary)
	titleLabel.TextSize = 12
	titleLabel.TextStyle = fyne.TextStyle{Bold: true}

	var header fyne.CanvasObject
	if badgeText != "" {
		badge := NewPillBadge(badgeText, badgeTextCol, badgeBgCol)
		header = container.NewBorder(nil, nil, titleLabel, badge)
	} else {
		header = titleLabel
	}

	valueLabel.TextStyle = fyne.TextStyle{Bold: true}
	valueLabel.Alignment = fyne.TextAlignLeading

	subLabel := canvas.NewText(subtitle, ColorTextMuted)
	subLabel.TextSize = 11

	cardContent := container.NewVBox(
		header,
		container.NewPadded(valueLabel),
		subLabel,
	)

	return container.NewStack(bg, container.NewPadded(cardContent))
}

// NewPanelCard cria um painel com fundo dark slate, borda arredondada e cabeçalho estilizado.
func NewPanelCard(title string, headerRight fyne.CanvasObject, body fyne.CanvasObject) fyne.CanvasObject {
	bg := canvas.NewRectangle(ColorCardBg)
	bg.CornerRadius = 10
	bg.StrokeColor = ColorCardBorder
	bg.StrokeWidth = 1.0

	titleText := canvas.NewText(title, ColorTextPrimary)
	titleText.TextSize = 13
	titleText.TextStyle = fyne.TextStyle{Bold: true}

	var header fyne.CanvasObject
	if headerRight != nil {
		header = container.NewBorder(nil, nil, titleText, headerRight)
	} else {
		header = titleText
	}

	content := container.NewVBox(
		header,
		canvas.NewLine(ColorCardBorder),
		body,
	)

	return container.NewStack(bg, container.NewPadded(content))
}
