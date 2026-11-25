//go:build windows

package watcher

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
	"secure-go/internal/cache"
	"secure-go/internal/hasher"
	"secure-go/internal/threatintel"
)

// AutorunEntry representa uma entrada configurada para inicialização automática com o Windows.
type AutorunEntry struct {
	Name         string        `json:"name"`
	Location     string        `json:"location"`
	Command      string        `json:"command"`
	FilePath     string        `json:"file_path"`
	SHA256       string        `json:"sha256"`
	Verdict      cache.Verdict `json:"verdict"`
	ThreatName   string        `json:"threat_name"`
	IsSuspicious bool          `json:"is_suspicious"`
	Source       string        `json:"source"`
}

type regTarget struct {
	root registry.Key
	path string
	name string
}

var autorunKeys = []regTarget{
	{registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, `HKCU\Run`},
	{registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\RunOnce`, `HKCU\RunOnce`},
	{registry.LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\Run`, `HKLM\Run`},
	{registry.LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\RunOnce`, `HKLM\RunOnce`},
}

// expandWindowsEnv substitui variáveis no formato %VAR% e $VAR por valores reais do sistema.
func expandWindowsEnv(s string) string {
	for {
		start := strings.Index(s, "%")
		if start == -1 {
			break
		}
		end := strings.Index(s[start+1:], "%")
		if end == -1 {
			break
		}
		end += start + 1
		varName := s[start+1 : end]
		val := os.Getenv(varName)
		if val == "" {
			val = os.Getenv(strings.ToUpper(varName))
		}
		if val == "" {
			val = os.Getenv(strings.ToLower(varName))
		}
		if val != "" {
			s = s[:start] + val + s[end+1:]
		} else {
			break
		}
	}
	return os.ExpandEnv(s)
}

// CleanExecutablePath extrai o caminho real do executável de uma linha de comando com parâmetros.
func CleanExecutablePath(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}

	// 1. Se começar com aspas: "C:\Path\app.exe" -arg
	if strings.HasPrefix(trimmed, "\"") {
		endQuote := strings.Index(trimmed[1:], "\"")
		if endQuote != -1 {
			return expandWindowsEnv(trimmed[1 : endQuote+1])
		}
	}

	// 2. Se tiver extensão .exe, localiza o fim do executável
	lower := strings.ToLower(trimmed)
	if idx := strings.Index(lower, ".exe"); idx != -1 {
		return expandWindowsEnv(strings.Trim(trimmed[:idx+4], "\""))
	}

	// 3. Fallback: primeiro token separado por espaço
	fields := strings.Fields(trimmed)
	if len(fields) > 0 {
		return expandWindowsEnv(strings.Trim(fields[0], "\""))
	}

	return expandWindowsEnv(trimmed)
}

// ScanAutoruns examina todas as chaves de registro Run e pastas de Startup do Windows.
func ScanAutoruns(ctx context.Context, engine *threatintel.Engine) ([]AutorunEntry, error) {
	var entries []AutorunEntry

	// 1. Varredura das Chaves de Registro
	for _, target := range autorunKeys {
		k, err := registry.OpenKey(target.root, target.path, registry.QUERY_VALUE)
		if err != nil {
			continue
		}

		valNames, err := k.ReadValueNames(0)
		if err == nil {
			for _, valName := range valNames {
				val, _, valErr := k.GetStringValue(valName)
				if valErr != nil || strings.TrimSpace(val) == "" {
					continue
				}

				cleanPath := CleanExecutablePath(val)
				entry := AutorunEntry{
					Name:     valName,
					Location: target.name,
					Command:  val,
					FilePath: cleanPath,
					Verdict:  cache.VerdictUnknown,
				}

				if cleanPath != "" {
					if stat, sErr := os.Stat(cleanPath); sErr == nil && !stat.IsDir() {
						if hash, hErr := hasher.ComputeFileSHA256(cleanPath); hErr == nil {
							entry.SHA256 = hash
							if engine != nil {
								// Consulta com timeout curto para cada autorun
								aCtx, aCancel := context.WithTimeout(ctx, 3*time.Second)
								res, aErr := engine.AnalyzeHash(aCtx, hash, filepath.Base(cleanPath), cleanPath, false)
								aCancel()
								if aErr == nil && res != nil {
									entry.Verdict = res.Verdict
									entry.ThreatName = res.ThreatName
									entry.Source = res.Source
									if res.Verdict == cache.VerdictMalicious || res.Verdict == cache.VerdictSuspicious {
										entry.IsSuspicious = true
									}
								}
							}
						}
					}
				}

				entries = append(entries, entry)
			}
		}
		k.Close()
	}

	// 2. Varredura da Pasta de Inicialização (Startup Folder)
	var startupDirs []string
	if appData := os.Getenv("APPDATA"); appData != "" {
		startupDirs = append(startupDirs, filepath.Join(appData, "Microsoft", "Windows", "Start Menu", "Programs", "Startup"))
	}
	if progData := os.Getenv("ProgramData"); progData != "" {
		startupDirs = append(startupDirs, filepath.Join(progData, "Microsoft", "Windows", "Start Menu", "Programs", "Startup"))
	}

	for _, sDir := range startupDirs {
		files, err := os.ReadDir(sDir)
		if err != nil {
			continue
		}

		for _, f := range files {
			if f.IsDir() {
				continue
			}
			fPath := filepath.Join(sDir, f.Name())
			entry := AutorunEntry{
				Name:     f.Name(),
				Location: "Pasta Startup",
				Command:  fPath,
				FilePath: fPath,
				Verdict:  cache.VerdictUnknown,
			}

			if hash, hErr := hasher.ComputeFileSHA256(fPath); hErr == nil {
				entry.SHA256 = hash
				if engine != nil {
					aCtx, aCancel := context.WithTimeout(ctx, 3*time.Second)
					res, aErr := engine.AnalyzeHash(aCtx, hash, f.Name(), fPath, false)
					aCancel()
					if aErr == nil && res != nil {
						entry.Verdict = res.Verdict
						entry.ThreatName = res.ThreatName
						entry.Source = res.Source
						if res.Verdict == cache.VerdictMalicious || res.Verdict == cache.VerdictSuspicious {
							entry.IsSuspicious = true
						}
					}
				}
			}

			entries = append(entries, entry)
		}
	}

	return entries, nil
}
