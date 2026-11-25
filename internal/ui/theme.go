package ui

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

// CustomTheme customiza a paleta de cores para um visual moderno de cibersegurança.
type CustomTheme struct {
	fyne.Theme
}

func NewCustomTheme() *CustomTheme {
	return &CustomTheme{Theme: theme.DefaultTheme()}
}

func (c *CustomTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	switch name {
	case theme.ColorNameBackground:
		return color.NRGBA{R: 20, G: 24, B: 33, A: 255} // Azul grafite escuro
	case theme.ColorNameInputBackground:
		return color.NRGBA{R: 30, G: 36, B: 48, A: 255}
	case theme.ColorNamePrimary:
		return color.NRGBA{R: 0, G: 168, B: 150, A: 255} // Turquesa cibersegurança
	case theme.ColorNameSuccess:
		return color.NRGBA{R: 46, G: 204, B: 113, A: 255} // Verde seguro
	case theme.ColorNameError:
		return color.NRGBA{R: 231, G: 76, B: 60, A: 255} // Vermelho alerta
	case theme.ColorNameWarning:
		return color.NRGBA{R: 243, G: 156, B: 18, A: 255} // Laranja suspeito
	default:
		return c.Theme.Color(name, theme.VariantDark)
	}
}
