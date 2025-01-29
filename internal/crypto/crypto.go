// crypto/crypto.go
package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"mobius/internal/utils"
	"os"
	"sync"
)

const (
	// KeySize is the size of AES-256 key in bytes
	KeySize = 32
	// NonceSize is the size of GCM nonce in bytes
	NonceSize = 12
)

var (
	ErrInvalidKey     = errors.New("invalid encryption key")
	ErrInvalidData    = errors.New("invalid encrypted data")
	ErrInvalidPadding = errors.New("invalid padding")
)

type CryptoManager struct {
	mu sync.RWMutex
}

func NewCryptoManager() *CryptoManager {
	return &CryptoManager{}
}

func (cm *CryptoManager) GetPeerPublicKey(peerID string) (*pem.Block, error) {
	keyDir := "keys"
	keyFile := fmt.Sprintf("%s/%s.pem", keyDir, peerID)

	// Read the public key from the file
	keyData, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key for peer %s: %w", peerID, err)
	}

	// Parse the PEM-encoded public key
	block, _ := pem.Decode(keyData)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("invalid public key format for peer %s", peerID)
	}

	return block, nil
}

// GenerateRandomBytes generates cryptographically secure random bytes
func GenerateRandomBytes(length int) ([]byte, error) {
	bytes := make([]byte, length)
	_, err := io.ReadFull(rand.Reader, bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return bytes, nil
}

// GenerateSymmetricKey generates a new AES-256 key
func (cm *CryptoManager) GenerateSymmetricKey() ([]byte, error) {
	return GenerateRandomBytes(KeySize)
}

// GenerateNonce generates a new GCM nonce
func (cm *CryptoManager) GenerateNonce() ([]byte, error) {
	return GenerateRandomBytes(NonceSize)
}

// EncryptKeyForPeer encrypts a symmetric key using RSA-OAEP
func (cm *CryptoManager) EncryptKeyForPeer(pubKey interface{}, key []byte) (string, error) {
	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return "", errors.New("provided key is not an RSA public key")
	}

	// Use SHA-256 for OAEP
	hash := sha256.New()
	encryptedKey, err := rsa.EncryptOAEP(hash, rand.Reader, rsaPubKey, key, nil)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt key: %w", err)
	}

	return base64.StdEncoding.EncodeToString(encryptedKey), nil
}

// DecryptKeyFromPeer decrypts a symmetric key using RSA-OAEP
func (cm *CryptoManager) DecryptKeyFromPeer(privateKey *rsa.PrivateKey, encryptedKey string) ([]byte, error) {
	// Decode base64 encrypted key
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted key: %w", err)
	}

	// Use SHA-256 for OAEP
	hash := sha256.New()
	decryptedKey, err := rsa.DecryptOAEP(hash, rand.Reader, privateKey, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt key: %w", err)
	}

	return decryptedKey, nil
}

func (cm *CryptoManager) Encrypt(message []byte, publicKeyPEM *pem.Block) ([]byte, error) {

	publicKey, err := x509.ParsePKIXPublicKey(publicKeyPEM.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaPubKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("parsed key is not an RSA public key")
	}

	// Use RSA-OAEP encryption
	encryptedMessage, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPubKey, message, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt message: %w", err)
	}

	return encryptedMessage, nil
}

func (cm *CryptoManager) Decrypt(encryptedMessage []byte) ([]byte, error) {
	block, _ := utils.GetPrivateKeyBlock()

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	decryptedMessage, err := rsa.DecryptOAEP(
		sha256.New(), rand.Reader, privateKey, encryptedMessage, nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt message: %w", err)
	}

	return decryptedMessage, nil
}
