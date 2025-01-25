// crypto/crypto.go
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
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
	mu             sync.RWMutex
	peerPublicKeys map[string]*rsa.PublicKey
	encryptionKeys map[string][]byte // Store encryption keys by file hash
}

func NewCryptoManager() *CryptoManager {
	return &CryptoManager{
		peerPublicKeys: make(map[string]*rsa.PublicKey),
		encryptionKeys: make(map[string][]byte),
	}
}

func (cm *CryptoManager) AddPeerPublicKey(peerID string, key *rsa.PublicKey) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.peerPublicKeys[peerID] = key
}

func (cm *CryptoManager) GetPeerPublicKey(peerID string) (*rsa.PublicKey, error) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	publicKey, exists := cm.peerPublicKeys[peerID]
	if !exists {
		return nil, fmt.Errorf("public key for peer %s not found", peerID)
	}
	return publicKey, nil
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

// EncryptFile encrypts a file using AES-256-GCM
func (cm *CryptoManager) EncryptFile(inputPath, outputPath string, key []byte) error {
	if len(key) != KeySize {
		return ErrInvalidKey
	}

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Create GCM mode
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate nonce
	nonce, err := cm.GenerateNonce()
	if err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Open input file
	input, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("failed to open input file: %w", err)
	}
	defer input.Close()

	// Read input file
	plaintext, err := io.ReadAll(input)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	// Encrypt data
	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)

	// Create output file
	err = os.WriteFile(outputPath, ciphertext, 0600)
	if err != nil {
		return fmt.Errorf("failed to write encrypted file: %w", err)
	}

	return nil
}

// DecryptFile decrypts a file using AES-256-GCM
func (cm *CryptoManager) DecryptFile(inputPath, outputPath string, key []byte) error {
	if len(key) != KeySize {
		return ErrInvalidKey
	}

	// Read encrypted file
	ciphertext, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("failed to read encrypted file: %w", err)
	}

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Create GCM mode
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	// Extract nonce from ciphertext
	if len(ciphertext) < NonceSize {
		return ErrInvalidData
	}
	nonce := ciphertext[:NonceSize]
	ciphertext = ciphertext[NonceSize:]

	// Decrypt data
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return fmt.Errorf("failed to decrypt data: %w", err)
	}

	// Write decrypted file
	err = os.WriteFile(outputPath, plaintext, 0600)
	if err != nil {
		return fmt.Errorf("failed to write decrypted file: %w", err)
	}

	return nil
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

func (cm *CryptoManager) RemovePeerPublicKey(peerID string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Check if the peer exists
	if _, exists := cm.peerPublicKeys[peerID]; exists {
		delete(cm.peerPublicKeys, peerID)
		log.Printf("Removed public key for peer: %s", peerID)
	} else {
		log.Printf("No public key found for peer: %s", peerID)
	}
}

func (cm *CryptoManager) StoreKeyForFile(fileHash string, key []byte) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Store the key for the file hash
	cm.encryptionKeys[fileHash] = key
	return nil
}

// Retrieve the encryption key for a file hash
func (cm *CryptoManager) GetKeyForFile(fileHash string) ([]byte, error) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	// Check if the key exists
	key, exists := cm.encryptionKeys[fileHash]
	if !exists {
		return nil, fmt.Errorf("no encryption key found for file hash: %s", fileHash)
	}
	return key, nil
}

func (cm *CryptoManager) Encrypt(message []byte, publicKeyPEM string) ([]byte, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("invalid public key PEM")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("key type is not RSA")
	}

	encryptedMessage, err := rsa.EncryptOAEP(
		sha256.New(), rand.Reader, rsaPublicKey, message, nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt message: %w", err)
	}

	return encryptedMessage, nil
}

func (cm *CryptoManager) Decrypt(encryptedMessage []byte, privateKeyPEM string) ([]byte, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("invalid private key PEM")
	}

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
