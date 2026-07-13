package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// Encryptor seals/opens small secrets (peer private keys) at rest using
// AES-256-GCM with a key supplied via the SECRET_KEY env var.
type Encryptor struct {
	gcm cipher.AEAD
}

func NewEncryptor(keyHex string) (*Encryptor, error) {
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("decode key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new gcm: %w", err)
	}
	return &Encryptor{gcm: gcm}, nil
}

// Seal encrypts plaintext, returning nonce||ciphertext.
func (e *Encryptor) Seal(plaintext string) ([]byte, error) {
	nonce := make([]byte, e.gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("read nonce: %w", err)
	}
	return e.gcm.Seal(nonce, nonce, []byte(plaintext), nil), nil
}

// Open decrypts a blob produced by Seal.
func (e *Encryptor) Open(blob []byte) (string, error) {
	n := e.gcm.NonceSize()
	if len(blob) < n {
		return "", fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := blob[:n], blob[n:]
	plaintext, err := e.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt: %w", err)
	}
	return string(plaintext), nil
}
