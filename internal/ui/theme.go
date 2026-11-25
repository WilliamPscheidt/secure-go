package ui

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

// Cores corporativas elegantes de Cibersegurança (Dark Slate Charcoal & Cyber Blue)
var (
	// Fundos em tons de cinza-escuro elegante e ardósia
	ColorSlateBg    = color.NRGBA{R: 15, G: 23, B: 42, A: 255}  // #0f172a - Cinza-escuro ardósia profundo
	ColorCardBg     = color.NRGBA{R: 24, G: 35, B: 54, A: 255}  // #182336 - Superfície dos Cards (Cinza-escuro elevado)
	ColorCardBorder = color.NRGBA{R: 44, G: 62, B: 92, A: 255}  // #2c3e5c - Borda moderna sutil
	ColorInputBg    = color.NRGBA{R: 13, G: 19, B: 33, A: 255}  // #0d1321 - Fundo escuro de inputs

	// Paleta de Acentos em Azul Moderno / Cyber Blue
	ColorBluePrimary = color.NRGBA{R: 59, G: 130, B: 246, A: 255} // #3b82f6 - Azul Tech Moderno
	ColorBlueHover   = color.NRGBA{R: 37, G: 99, B: 235, A: 255}  // #2563eb - Azul Escuro Hover
	ColorBlueVibrant = color.NRGBA{R: 96, G: 165, B: 250, A: 255} // #60a5fa - Azul Claro para Destaques
	ColorBlueAlpha   = color.NRGBA{R: 59, G: 130, B: 246, A: 35}  // #3b82f623 - Brilho translúcido azul
	ColorCyan        = color.NRGBA{R: 56, G: 189, B: 248, A: 255} // #38bdf8 - Azul Ciano / Sky
	ColorCyanAlpha   = color.NRGBA{R: 56, G: 189, B: 248, A: 35}  // #38bdf823 - Ciano translúcido

	// Aliases para compatibilidade visual com o novo esquema azul
	ColorEmerald      = ColorCyan
	ColorEmeraldHover = ColorBlueHover
	ColorEmeraldSoft  = ColorBlueVibrant
	ColorEmeraldAlpha = ColorCyanAlpha

	// Tipografia de alto contraste e legibilidade
	ColorTextPrimary   = color.NRGBA{R: 248, G: 250, B: 252, A: 255} // #f8fafc - Branco Platinum
	ColorTextSecondary = color.NRGBA{R: 148, G: 163, B: 184, A: 255} // #94a3b8 - Cinza suave
	ColorTextMuted     = color.NRGBA{R: 100, G: 116, B: 139, A: 255} // #64748b - Texto atenuado

	// Vereditos e Alertas
	ColorDanger   = color.NRGBA{R: 244, G: 63, B: 94, A: 255}  // #f43f5e - Vermelho Carmesim Tech
	ColorDangerBg = color.NRGBA{R: 244, G: 63, B: 94, A: 32}  // Vermelho translúcido suave
	ColorWarn     = color.NRGBA{R: 245, G: 158, B: 11, A: 255} // #f59e0b - Âmbar Suave
	ColorWarnBg   = color.NRGBA{R: 245, G: 158, B: 11, A: 32}
	ColorInfo     = color.NRGBA{R: 56, G: 189, B: 248, A: 255} // #38bdf8 - Ciano Elétrico
	ColorInfoBg   = color.NRGBA{R: 56, G: 189, B: 248, A: 32}
)

// CustomTheme implementa o tema Dark Slate profissional com acentos em cinza-escuro e azul tech.
type CustomTheme struct {
	fyne.Theme
}

func NewCustomTheme() *CustomTheme {
	return &CustomTheme{Theme: theme.DefaultTheme()}
}

func (c *CustomTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	switch name {
	case theme.ColorNameBackground:
		return ColorSlateBg

	case theme.ColorNameInputBackground:
		return ColorInputBg

	case theme.ColorNamePrimary:
		return ColorBluePrimary

	case theme.ColorNameFocus:
		return ColorBlueVibrant

	case theme.ColorNameSelection:
		return ColorBlueAlpha

	case theme.ColorNameSuccess:
		return ColorCyan

	case theme.ColorNameError:
		return ColorDanger

	case theme.ColorNameWarning:
		return ColorWarn

	case theme.ColorNameForeground:
		return ColorTextPrimary

	case theme.ColorNameButton:
		return color.NRGBA{R: 28, G: 42, B: 66, A: 255} // Botão cinza-azulado moderno

	case theme.ColorNameDisabled:
		return color.NRGBA{R: 71, G: 85, B: 105, A: 255}

	case theme.ColorNameDisabledButton:
		return color.NRGBA{R: 20, G: 28, B: 40, A: 255}

	case theme.ColorNameSeparator:
		return ColorCardBorder

	case theme.ColorNameMenuBackground, theme.ColorNameOverlayBackground:
		return color.NRGBA{R: 15, G: 23, B: 42, A: 255}

	case theme.ColorNameScrollBar:
		return color.NRGBA{R: 59, G: 130, B: 246, A: 120}

	case theme.ColorNameShadow:
		return color.NRGBA{R: 0, G: 0, B: 0, A: 160}

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
		return 8
	case theme.SizeNameScrollBarSmall:
		return 4
	default:
		return c.Theme.Size(name)
	}
}
