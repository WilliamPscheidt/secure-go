package ui

import (
	"image/color"
	"os"
	"path/filepath"
	"sync"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

// Cores refinadas inspiradas no Malwarebytes Premium & Purrweb Antivirus Design
var (
	// Fundos em tons de ardósia obsidiana profunda e charcoals elegantes
	ColorSlateBg    = color.NRGBA{R: 12, G: 16, B: 23, A: 255}  // #0c1017 - Fundo principal da aplicação
	ColorSidebarBg  = color.NRGBA{R: 8, G: 11, B: 16, A: 255}   // #080b10 - Sidebar lateral mais escura
	ColorCardBg     = color.NRGBA{R: 20, G: 26, B: 37, A: 255}  // #141a25 - Superfície elevada dos cards
	ColorCardHover  = color.NRGBA{R: 27, G: 35, B: 50, A: 255}  // #1b2332 - Hover sutil em cards
	ColorCardBorder = color.NRGBA{R: 35, G: 46, B: 64, A: 255}  // #232e40 - Contorno sutil e moderno de 1px
	ColorInputBg    = color.NRGBA{R: 14, G: 19, B: 28, A: 255}  // #0e131c - Fundo de campos de texto

	// Paleta de Acentos: Cyber Blue & Emerald Green (Score de Proteção)
	ColorBluePrimary = color.NRGBA{R: 37, G: 99, B: 235, A: 255}  // #2563eb - Azul Tech Purrweb / Malwarebytes
	ColorBlueHover   = color.NRGBA{R: 29, G: 78, B: 216, A: 255}  // #1d4ed8 - Azul escuro hover
	ColorBlueVibrant = color.NRGBA{R: 59, G: 130, B: 246, A: 255} // #3b82f6 - Azul claro vivo para títulos
	ColorBlueAlpha   = color.NRGBA{R: 59, G: 130, B: 246, A: 35}  // Brilho translúcido azul

	// Verde Esmeralda / Neon do Score 100% de Proteção (Malwarebytes Trusted Advisor)
	ColorScoreGreen   = color.NRGBA{R: 16, G: 185, B: 129, A: 255} // #10b981 - Verde proteção excelente
	ColorScoreGreenBg = color.NRGBA{R: 16, G: 185, B: 129, A: 30}  // Fundo translúcido
	ColorCyan         = color.NRGBA{R: 6, G: 182, B: 212, A: 255}  // #06b6d4 - Ciano moderno
	ColorCyanAlpha    = color.NRGBA{R: 6, G: 182, B: 212, A: 35}

	// Aliases para compatibilidade visual
	ColorEmerald      = ColorScoreGreen
	ColorEmeraldHover = ColorBlueHover
	ColorEmeraldSoft  = ColorScoreGreen
	ColorEmeraldAlpha = ColorScoreGreenBg

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
	case theme.SizeNameText:
		return 13
	case theme.SizeNameHeadingText:
		return 18
	case theme.SizeNameSubHeadingText:
		return 14
	case theme.SizeNameCaptionText:
		return 11
	default:
		return c.Theme.Size(name)
	}
}

var (
	fontRegular    fyne.Resource
	fontBold       fyne.Resource
	fontItalic     fyne.Resource
	fontBoldItalic fyne.Resource
	fontMonospace  fyne.Resource
	fontOnce       sync.Once
)

func initFonts() {
	windir := os.Getenv("WINDIR")
	if windir == "" {
		windir = "C:\\Windows"
	}
	fontsDir := filepath.Join(windir, "Fonts")

	loadFont := func(resName string, filenames ...string) fyne.Resource {
		for _, fn := range filenames {
			p := filepath.Join(fontsDir, fn)
			data, err := os.ReadFile(p)
			if err == nil && len(data) > 0 {
				return fyne.NewStaticResource(resName, data)
			}
		}
		return nil
	}

	// Segoe UI (Tipografia moderna e nítida do Windows 11 / Fluent Design)
	fontRegular = loadFont("SegoeUI-Regular.ttf", "segoeui.ttf", "aptos.ttf", "calibri.ttf")
	fontBold = loadFont("SegoeUI-Bold.ttf", "segoeuib.ttf", "aptos-bold.ttf", "calibrib.ttf")
	fontItalic = loadFont("SegoeUI-Italic.ttf", "segoeuii.ttf", "aptos-italic.ttf", "calibrii.ttf")
	fontBoldItalic = loadFont("SegoeUI-BoldItalic.ttf", "segoeuiz.ttf", "calibriz.ttf")
	fontMonospace = loadFont("Consolas.ttf", "consola.ttf", "CascadiaMono.ttf", "cour.ttf")
}

// Font retorna a tipografia oficial moderna Segoe UI para toda a interface do aplicativo.
func (c *CustomTheme) Font(style fyne.TextStyle) fyne.Resource {
	fontOnce.Do(initFonts)

	if style.Monospace && fontMonospace != nil {
		return fontMonospace
	}
	if style.Bold && style.Italic && fontBoldItalic != nil {
		return fontBoldItalic
	}
	if style.Bold && fontBold != nil {
		return fontBold
	}
	if style.Italic && fontItalic != nil {
		return fontItalic
	}
	if fontRegular != nil {
		return fontRegular
	}
	return c.Theme.Font(style)
}
