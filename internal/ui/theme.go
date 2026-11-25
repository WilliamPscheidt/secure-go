package ui

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

// Cores corporativas elegantes de Cibersegurança (Emerald & Dark Slate)
var (
	ColorSlateBg      = color.NRGBA{R: 11, G: 17, B: 28, A: 255}  // #0b111c - Fundo Dark Slate profundo
	ColorCardBg       = color.NRGBA{R: 18, G: 27, B: 43, A: 255}  // #121b2b - Superfície dos Cards
	ColorCardBorder   = color.NRGBA{R: 33, G: 48, B: 71, A: 255}  // #213047 - Borda sutil dos Cards
	ColorInputBg      = color.NRGBA{R: 14, G: 21, B: 34, A: 255}  // #0e1522 - Fundo de Inputs

	ColorEmerald      = color.NRGBA{R: 16, G: 185, B: 129, A: 255} // #10b981 - Verde Esmeralda Suave
	ColorEmeraldHover = color.NRGBA{R: 5, G: 150, B: 105, A: 255}  // #059669 - Esmeralda Escuro
	ColorEmeraldSoft  = color.NRGBA{R: 52, G: 211, B: 153, A: 255} // #34d399 - Verde Menta para Destaques
	ColorEmeraldAlpha = color.NRGBA{R: 16, G: 185, B: 129, A: 35}  // #10b98123 - Brilho translúcido suave

	ColorTextPrimary   = color.NRGBA{R: 248, G: 250, B: 252, A: 255} // #f8fafc - Branco Platinum
	ColorTextSecondary = color.NRGBA{R: 148, G: 163, B: 184, A: 255} // #94a3b8 - Cinza ardósia suave
	ColorTextMuted     = color.NRGBA{R: 100, G: 116, B: 139, A: 255} // #64748b - Texto secundário

	ColorDanger   = color.NRGBA{R: 239, G: 68, B: 68, A: 255}   // #ef4444 - Vermelho Alerta
	ColorDangerBg = color.NRGBA{R: 239, G: 68, B: 68, A: 30}   // Vermelho translúcido suave
	ColorWarn     = color.NRGBA{R: 245, G: 158, B: 11, A: 255}  // #f59e0b - Âmbar Suave
	ColorWarnBg   = color.NRGBA{R: 245, G: 158, B: 11, A: 30}
	ColorInfo     = color.NRGBA{R: 56, G: 189, B: 248, A: 255}   // #38bdf8 - Azul Ciano Suave
	ColorInfoBg   = color.NRGBA{R: 56, G: 189, B: 248, A: 30}
)

// CustomTheme implementa o tema Dark Slate profissional com acentos em verde esmeralda suave.
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
		return ColorEmerald

	case theme.ColorNameFocus:
		return ColorEmeraldSoft

	case theme.ColorNameSelection:
		return ColorEmeraldAlpha

	case theme.ColorNameSuccess:
		return ColorEmerald

	case theme.ColorNameError:
		return ColorDanger

	case theme.ColorNameWarning:
		return ColorWarn

	case theme.ColorNameForeground:
		return ColorTextPrimary

	case theme.ColorNameButton:
		return color.NRGBA{R: 24, G: 35, B: 52, A: 255} // Botão suave escuro

	case theme.ColorNameDisabled:
		return color.NRGBA{R: 71, G: 85, B: 105, A: 255}

	case theme.ColorNameDisabledButton:
		return color.NRGBA{R: 20, G: 28, B: 40, A: 255}

	case theme.ColorNameSeparator:
		return ColorCardBorder

	case theme.ColorNameMenuBackground, theme.ColorNameOverlayBackground:
		return color.NRGBA{R: 15, G: 23, B: 36, A: 255}

	case theme.ColorNameScrollBar:
		return color.NRGBA{R: 16, G: 185, B: 129, A: 100}

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
