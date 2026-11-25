package ui

import (
	"fmt"
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

// NewSectionHeader cria um título de seção no estilo limpo e profissional do Malwarebytes.
func NewSectionHeader(title string) fyne.CanvasObject {
	t := canvas.NewText(title, ColorTextMuted)
	t.TextSize = 11
	t.TextStyle = fyne.TextStyle{Bold: true}
	return container.NewPadded(t)
}

// NewPillBadge cria uma etiqueta arredondada no estilo "pill" moderno.
func NewPillBadge(text string, textColor, bgColor color.Color) fyne.CanvasObject {
	bg := canvas.NewRectangle(bgColor)
	bg.CornerRadius = 12
	bg.StrokeColor = textColor
	bg.StrokeWidth = 0.5

	lbl := canvas.NewText(text, textColor)
	lbl.TextStyle = fyne.TextStyle{Bold: true}
	lbl.TextSize = 10

	content := container.NewCenter(lbl)
	return container.NewStack(bg, container.NewPadded(content))
}

// NewSecurityRowCard cria um cartão horizontal com ícone, título, subtítulo e ação (estilo Malwarebytes Security).
func NewSecurityRowCard(icon fyne.Resource, title, subtitle string, actionWidget fyne.CanvasObject, extraBottom fyne.CanvasObject) fyne.CanvasObject {
	bg := canvas.NewRectangle(ColorCardBg)
	bg.CornerRadius = 10
	bg.StrokeColor = ColorCardBorder
	bg.StrokeWidth = 1.0

	var iconBox fyne.CanvasObject
	if icon != nil {
		iconImg := canvas.NewImageFromResource(icon)
		iconImg.SetMinSize(fyne.NewSize(22, 22))

		iconBg := canvas.NewRectangle(ColorCardHover)
		iconBg.CornerRadius = 8
		iconBox = container.NewStack(iconBg, container.NewCenter(iconImg))
	}

	titleLabel := canvas.NewText(title, ColorTextPrimary)
	titleLabel.TextSize = 13
	titleLabel.TextStyle = fyne.TextStyle{Bold: true}

	subLabel := canvas.NewText(subtitle, ColorTextSecondary)
	subLabel.TextSize = 11

	textCol := container.NewVBox(titleLabel, subLabel)

	var leftSide fyne.CanvasObject
	if iconBox != nil {
		leftSide = container.NewHBox(iconBox, textCol)
	} else {
		leftSide = textCol
	}

	var row fyne.CanvasObject
	if actionWidget != nil {
		row = container.NewBorder(nil, nil, leftSide, container.NewCenter(actionWidget))
	} else {
		row = leftSide
	}

	var fullContent fyne.CanvasObject
	if extraBottom != nil {
		fullContent = container.NewVBox(row, extraBottom)
	} else {
		fullContent = row
	}

	return container.NewStack(bg, container.NewPadded(fullContent))
}

// NewMetricCard cria um cartão moderno com fundo elevado, borda sutil, métrica grande e badge.
func NewMetricCard(title, subtitle string, valueLabel *widget.Label, badgeText string, badgeTextCol, badgeBgCol color.Color) fyne.CanvasObject {
	bg := canvas.NewRectangle(ColorCardBg)
	bg.CornerRadius = 10
	bg.StrokeColor = ColorCardBorder
	bg.StrokeWidth = 1.0

	titleLabel := canvas.NewText(title, ColorTextSecondary)
	titleLabel.TextSize = 11
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

// NewProtectionScoreGauge constrói o medidor em arco circular do Trusted Advisor (Score de Proteção 100%).
func NewProtectionScoreGauge(score int, statusText string) fyne.CanvasObject {
	bg := canvas.NewRectangle(ColorCardBg)
	bg.CornerRadius = 10
	bg.StrokeColor = ColorCardBorder
	bg.StrokeWidth = 1.0

	// Arco em ferradura / velocímetro (de -135° na base esquerda até +135° na base direita = 270° de amplitude total)
	startAngle := float32(-135)
	endAngle := float32(135)
	totalSpan := endAngle - startAngle // 270 graus

	// Trilho de fundo (cinza escuro sutil)
	trackArc := canvas.NewArc(startAngle, endAngle, 0.82, ColorCardBorder)
	trackArc.CornerRadius = canvas.RadiusMaximum
	trackArc.SetMinSize(fyne.NewSize(160, 140))

	// Cor do preenchimento baseada no score
	fillCol := ColorScoreGreen
	if score < 70 {
		fillCol = ColorWarn
	}
	if score < 40 {
		fillCol = ColorDanger
	}

	// Arco preenchido proporcional ao score
	fillSpan := totalSpan * float32(score) / 100.0
	fillEnd := startAngle + fillSpan
	if fillEnd <= startAngle {
		fillEnd = startAngle + 0.1
	}

	fillArc := canvas.NewArc(startAngle, fillEnd, 0.82, fillCol)
	fillArc.CornerRadius = canvas.RadiusMaximum
	fillArc.SetMinSize(fyne.NewSize(160, 140))

	gaugeStack := container.NewStack(trackArc, fillArc)

	lblScoreLabel := canvas.NewText("Protection score", ColorTextMuted)
	lblScoreLabel.TextSize = 11

	lblScoreVal := canvas.NewText(fmt.Sprintf("%d%%", score), ColorTextPrimary)
	lblScoreVal.TextSize = 26
	lblScoreVal.TextStyle = fyne.TextStyle{Bold: true}

	lblScoreStatus := canvas.NewText(statusText, fillCol)
	lblScoreStatus.TextSize = 12
	lblScoreStatus.TextStyle = fyne.TextStyle{Bold: true}

	gaugeCenterText := container.NewVBox(
		container.NewCenter(lblScoreLabel),
		container.NewCenter(lblScoreVal),
		container.NewCenter(lblScoreStatus),
	)

	gaugeCombined := container.NewStack(
		container.NewCenter(gaugeStack),
		container.NewCenter(gaugeCenterText),
	)

	item1 := container.NewHBox(canvas.NewText("✔", ColorScoreGreen), canvas.NewText("Monitoramento em tempo real ativo", ColorTextSecondary))
	item2 := container.NewHBox(canvas.NewText("✔", ColorScoreGreen), canvas.NewText("Heurística Authenticode operacional", ColorTextSecondary))
	item3 := container.NewHBox(canvas.NewText("✔", ColorScoreGreen), canvas.NewText("Motor de Regras YARA offline ativo", ColorTextSecondary))
	item4 := container.NewHBox(canvas.NewText("✔", ColorScoreGreen), canvas.NewText("Inteligência Abuse.ch + VirusTotal", ColorTextSecondary))

	checklist := container.NewVBox(item1, item2, item3, item4)

	headerTitle := canvas.NewText("Este Computador", ColorTextPrimary)
	headerTitle.TextSize = 13
	headerTitle.TextStyle = fyne.TextStyle{Bold: true}

	headerBadge := canvas.NewText(fmt.Sprintf("%d%% Protegido", score), fillCol)
	headerBadge.TextSize = 12
	headerBadge.TextStyle = fyne.TextStyle{Bold: true}

	cardBody := container.NewVBox(
		container.NewBorder(nil, nil, headerTitle, headerBadge),
		canvas.NewLine(ColorCardBorder),
		container.NewPadded(gaugeCombined),
		canvas.NewLine(ColorCardBorder),
		checklist,
	)

	return container.NewStack(bg, container.NewPadded(cardBody))
}

// NewPanelCard cria um painel com fundo dark slate, borda arredondada e cabeçalho estilizado.
func NewPanelCard(title string, headerRight fyne.CanvasObject, body fyne.CanvasObject) fyne.CanvasObject {
	bg := canvas.NewRectangle(ColorCardBg)
	bg.CornerRadius = 10
	bg.StrokeColor = ColorCardBorder
	bg.StrokeWidth = 1.0

	titleText := canvas.NewText(title, ColorTextPrimary)
	titleText.TextSize = 12
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
