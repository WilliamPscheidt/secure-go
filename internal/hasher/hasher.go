package hasher

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

const bufferSize = 64 * 1024 // 64KB buffer para leitura eficiente

// ComputeFileSHA256 calcula o hash SHA-256 de um arquivo em disco via streaming.
func ComputeFileSHA256(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("erro ao abrir arquivo para hash: %w", err)
	}
	defer file.Close()

	hasher := sha256.New()
	buf := make([]byte, bufferSize)

	if _, err := io.CopyBuffer(hasher, file, buf); err != nil {
		return "", fmt.Errorf("erro ao calcular hash: %w", err)
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// ComputeBytesSHA256 calcula o hash SHA-256 de uma sequência de bytes na memória.
func ComputeBytesSHA256(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}
