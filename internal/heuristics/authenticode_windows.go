package heuristics

import (
	"syscall"
	"unsafe"
)

var (
	modWintrust        = syscall.NewLazyDLL("wintrust.dll")
	procWinVerifyTrust = modWintrust.NewProc("WinVerifyTrust")
)

var (
	// WINTRUST_ACTION_GENERIC_VERIFY_V2: {00AAC56B-CD44-11d0-8CC2-00C04FC295EE}
	wintrustActionGenericVerifyV2 = syscall.GUID{
		Data1: 0x00aac56b,
		Data2: 0xcd44,
		Data3: 0x11d0,
		Data4: [8]byte{0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee},
	}
)

const (
	WTD_CHOICE_FILE               = 1
	WTD_UI_NONE                   = 2
	WTD_REVOKE_NONE               = 0
	WTD_STATEACTION_IGNORE        = 0
	WTD_SAFER_FLAG                = 0x00000100
	WTD_CACHE_ONLY_URL_RETRIEVAL  = 0x00001000

	// Códigos de retorno de verificação
	ERROR_SUCCESS                 = 0
	TRUST_E_NOSIGNATURE           = 0x800B0100
	TRUST_E_EXPLICIT_DISTRUST     = 0x800B0111
	CERT_E_EXPIRED                = 0x800B0101
	TRUST_E_BAD_DIGEST            = 0x80096010
	TRUST_E_PROVIDER_UNKNOWN      = 0x800B0001
	CRYPT_E_SECURITY_SETTINGS     = 0x80092026
)

type wintrustFileInfo struct {
	cbStruct       uint32
	pcwszFilePath  *uint16
	hFile          syscall.Handle
	pgKnownSubject uintptr
}

type wintrustData struct {
	cbStruct            uint32
	pPolicyCallbackData uintptr
	pSIPClientData      uintptr
	dwUIChoice          uint32
	fdwRevocationChecks uint32
	dwUnionChoice       uint32
	pFile               uintptr
	dwStateAction       uint32
	hWVTStateData       syscall.Handle
	pwszURLReference    *uint16
	dwProvFlags         uint32
	dwUIContext         uint32
	pSignatureSettings  uintptr
}

// SignatureStatus descreve o estado da assinatura digital Authenticode de um executável.
type SignatureStatus string

const (
	SigStatusValidTrusted   SignatureStatus = "VALID_TRUSTED"   // Válida e assinada por autoridade confiável
	SigStatusUnsigned       SignatureStatus = "UNSIGNED"        // Sem assinatura digital
	SigStatusUntrusted      SignatureStatus = "UNTRUSTED"       // Assinatura não confiável ou revogada
	SigStatusExpired        SignatureStatus = "EXPIRED"         // Certificado expirado
	SigStatusCorrupt        SignatureStatus = "CORRUPT_DIGEST"  // Arquivo alterado após assinatura (adulterado)
	SigStatusUnknown        SignatureStatus = "UNKNOWN_ERROR"   // Erro desconhecido ou arquivo inacessível
)

// SignatureInfo armazena os dados consolidados da assinatura do arquivo.
type SignatureInfo struct {
	IsSigned    bool            `json:"is_signed"`
	IsTrusted   bool            `json:"is_trusted"`
	Status      SignatureStatus `json:"status"`
	Description string          `json:"description"`
}

// VerifyAuthenticode examina a assinatura digital de um binário no disco usando a API nativa WinVerifyTrust.
func VerifyAuthenticode(filePath string) SignatureInfo {
	if filePath == "" {
		return SignatureInfo{
			IsSigned:    false,
			IsTrusted:   false,
			Status:      SigStatusUnknown,
			Description: "Caminho de arquivo inválido",
		}
	}

	pPath, err := syscall.UTF16PtrFromString(filePath)
	if err != nil {
		return SignatureInfo{
			IsSigned:    false,
			IsTrusted:   false,
			Status:      SigStatusUnknown,
			Description: "Falha ao codificar caminho para UTF-16",
		}
	}

	fileInfo := wintrustFileInfo{
		cbStruct:      uint32(unsafe.Sizeof(wintrustFileInfo{})),
		pcwszFilePath: pPath,
	}

	wvtData := wintrustData{
		cbStruct:            uint32(unsafe.Sizeof(wintrustData{})),
		dwUIChoice:          WTD_UI_NONE,
		fdwRevocationChecks: WTD_REVOKE_NONE,
		dwUnionChoice:       WTD_CHOICE_FILE,
		pFile:               uintptr(unsafe.Pointer(&fileInfo)),
		dwStateAction:       WTD_STATEACTION_IGNORE,
		dwProvFlags:         WTD_SAFER_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL,
	}

	ret, _, _ := procWinVerifyTrust.Call(
		uintptr(0), // HWND_DESKTOP
		uintptr(unsafe.Pointer(&wintrustActionGenericVerifyV2)),
		uintptr(unsafe.Pointer(&wvtData)),
	)

	errCode := uint32(ret)
	if errCode == ERROR_SUCCESS {
		return SignatureInfo{
			IsSigned:    true,
			IsTrusted:   true,
			Status:      SigStatusValidTrusted,
			Description: "Assinatura digital válida e confiável (Authenticode)",
		}
	}

	switch errCode {
	case TRUST_E_NOSIGNATURE:
		return SignatureInfo{
			IsSigned:    false,
			IsTrusted:   false,
			Status:      SigStatusUnsigned,
			Description: "Binário não assinado digitalmente",
		}
	case TRUST_E_EXPLICIT_DISTRUST, CRYPT_E_SECURITY_SETTINGS:
		return SignatureInfo{
			IsSigned:    true,
			IsTrusted:   false,
			Status:      SigStatusUntrusted,
			Description: "Assinatura explicitamente não confiável ou revogada",
		}
	case CERT_E_EXPIRED:
		return SignatureInfo{
			IsSigned:    true,
			IsTrusted:   false,
			Status:      SigStatusExpired,
			Description: "Certificado digital expirado",
		}
	case TRUST_E_BAD_DIGEST:
		return SignatureInfo{
			IsSigned:    true,
			IsTrusted:   false,
			Status:      SigStatusCorrupt,
			Description: "ALERTA: Hash adulterado/corrompido após a assinatura!",
		}
	default:
		return SignatureInfo{
			IsSigned:    false,
			IsTrusted:   false,
			Status:      SigStatusUnsigned,
			Description: "Binário sem certificado Authenticode válido",
		}
	}
}
