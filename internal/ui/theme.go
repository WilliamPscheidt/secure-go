package ui

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

// CustomTheme implementa um tema Dark-Mode moderno com estética cyberpunk/hacker em tons de verde neon.
type CustomTheme struct {
	fyne.Theme
}

func NewCustomTheme() *CustomTheme {
	return &CustomTheme{Theme: theme.DefaultTheme()}
}

func (c *CustomTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	switch name {
	// Fundo principal OLED / Dark Slate profundo
	case theme.ColorNameBackground:
		return color.NRGBA{R: 10, G: 14, B: 19, A: 255} // #0a0e13

	// Fundo de inputs e caixas de texto
	case theme.ColorNameInputBackground:
		return color.NRGBA{R: 16, G: 23, B: 30, A: 255} // #10171e

	// Cor primária: Verde Esmeralda Neon Cyberpunk
	case theme.ColorNamePrimary:
		return color.NRGBA{R: 0, G: 230, B: 118, A: 255} // #00e676 (Neon Green)

	// Foco e seleção com brilho verde neon
	case theme.ColorNameFocus:
		return color.NRGBA{R: 0, G: 255, B: 136, A: 255} // #00ff88

	case theme.ColorNameSelection:
		return color.NRGBA{R: 0, G: 230, B: 118, A: 60} // Verde translúcido para destaques

	// Sucesso / Limpo / Seguro
	case theme.ColorNameSuccess:
		return color.NRGBA{R: 0, G: 230, B: 118, A: 255}

	// Alertas de Malware
	case theme.ColorNameError:
		return color.NRGBA{R: 255, G: 61, B: 87, A: 255} // #ff3d57 (Neon Red)

	// Suspeito
	case theme.ColorNameWarning:
		return color.NRGBA{R: 255, G: 179, B: 0, A: 255} // #ffb300 (Amber Neon)

	// Texto principal: Branco puro nítido
	case theme.ColorNameForeground:
		return color.NRGBA{R: 240, G: 246, B: 252, A: 255} // #f0f6fc

	// Fundo de botões secundários
	case theme.ColorNameButton:
		return color.NRGBA{R: 18, G: 28, B: 24, A: 255} // Slate escuro com leve toque esmeralda

	// Desabilitados
	case theme.ColorNameDisabled:
		return color.NRGBA{R: 70, G: 80, B: 90, A: 255}

	case theme.ColorNameDisabledButton:
		return color.NRGBA{R: 20, G: 26, B: 32, A: 255}

	// Separadores e bordas sutis
	case theme.ColorNameSeparator:
		return color.NRGBA{R: 24, G: 38, B: 32, A: 255}

	// Fundo de menus e popups
	case theme.ColorNameMenuBackground, theme.ColorNameOverlayBackground:
		return color.NRGBA{R: 14, G: 20, B: 26, A: 255}

	// Barra de rolagem estilizada
	case theme.ColorNameScrollBar:
		return color.NRGBA{R: 0, G: 200, B: 100, A: 120}

	case theme.ColorNameShadow:
		return color.NRGBA{R: 0, G: 0, B: 0, A: 180}

	default:
		return c.Theme.Color(name, theme.VariantDark)
	}
}

func (c *CustomTheme) Size(name fyne.ThemeSizeName) float32 {
	switch name {
	case theme.SizeNamePadding:
		return 8
	case theme.SizeNameInnerPadding:
		return 6
	case theme.SizeNameScrollBar:
		return 10
	case theme.SizeNameScrollBarSmall:
		return 4
	default:
		return c.Theme.Size(name)
	}
}
