package utils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/gob"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ipfs/go-cid"
	libp2pnetwork "github.com/libp2p/go-libp2p/core/network"
	"github.com/mr-tron/base58"
	"github.com/multiformats/go-multihash"
	mh "github.com/multiformats/go-multihash"
)

type MessageType int

const (
	RequestFile MessageType = iota
	FileResponse
	ErrorResponse
)

type Message struct {
	Type     MessageType
	Hash     string
	Error    string
	Filename string
}

// Helper function to copy a file
func CopyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destinationFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destinationFile.Close()

	_, err = io.Copy(destinationFile, sourceFile)
	return err
}

func GenerateFileHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", fmt.Errorf("failed to compute hash: %w", err)
	}

	rawHash := hasher.Sum(nil)
	multihash, err := mh.Encode(rawHash, mh.SHA2_256)
	if err != nil {
		return "", fmt.Errorf("failed to encode multihash: %w", err)
	}

	return base58.Encode(multihash), nil
}

func WriteMessage(stream libp2pnetwork.Stream, msg *Message) error {
	return gob.NewEncoder(stream).Encode(msg)
}

func ReadMessage(stream libp2pnetwork.Stream) (*Message, error) {
	var msg Message
	err := gob.NewDecoder(stream).Decode(&msg)
	return &msg, err
}

func isValidIPNSKey(key string) bool {
	// Basic IPNS key validation
	if !strings.HasPrefix(key, "/ipns/") {
		return false
	}

	// The key should be longer than just "/ipns/"
	if len(key) <= 6 {
		return false
	}

	// The hash part should be base58 encoded and of proper length
	hash := strings.TrimPrefix(key, "/ipns/")
	return len(hash) >= 46 && len(hash) <= 49 // Base58 encoded SHA-256 length range
}

func HashKey(key string) (string, error) {
	// Sanitize the input key
	key = strings.TrimSpace(key)
	if key == "" {
		return "", fmt.Errorf("key cannot be empty")
	}

	// Add a prefix if the key doesn't already have one
	if !strings.HasPrefix(key, "/") {
		key = "/" + key
	}

	// Use SHA2-256 with proper length specification
	hashed, err := mh.Sum([]byte(key), mh.SHA2_256, 32)
	if err != nil {
		return "", fmt.Errorf("failed to hash key: %w", err)
	}

	ipnsKey := "/ipns/" + hashed.B58String()

	// Validate the generated IPNS key format
	if !isValidIPNSKey(ipnsKey) {
		return "", fmt.Errorf("generated invalid IPNS key format: %s", ipnsKey)
	}

	return ipnsKey, nil
}

func StringInSlice(a string, list []string) bool {

	for _, b := range list {

		if b == a {

			return true

		}

	}

	return false

}

func GenerateFileCID(filePath string) (cid.Cid, error) {
	// Read file contents
	fileBytes, err := os.ReadFile(filePath)
	if err != nil {
		return cid.Undef, err
	}

	// Create a CID using the file contents
	fileCid, err := cid.V1Builder{
		Codec:  cid.Raw,
		MhType: multihash.SHA2_256,
	}.Sum(fileBytes)
	if err != nil {
		return cid.Undef, err
	}

	return fileCid, nil
}

// GenerateNewKeyPair generates an ECDSA key pair and returns PEM-encoded public and private keys.
func GenerateNewKeyPair() (string, string, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate key pair: %w", err)
	}

	// Marshal private key to PEM
	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to encode private key: %w", err)
	}
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// Marshal public key to PEM
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to encode public key: %w", err)
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return string(publicKeyPEM), string(privateKeyPEM), nil
}

func GetOwnKeysFromDisk() (string, string, error) {
	publicKeyFile := "keys/pubk.pub"
	privateKeyFile := "keys/privk.key"

	// Attempt to read the key from disk
	publicKey, pb_err := os.ReadFile(publicKeyFile)
	privateKey, pv_err := os.ReadFile(privateKeyFile)
	if pb_err == nil || pv_err == nil {
		return string(publicKey), string(privateKey), nil
	}

	if os.IsNotExist(pv_err) && os.IsNotExist(pb_err) {
		// Key does not exist, generate a new one
		newPublicKey, newPrivateKey, genErr := GenerateNewKeyPair()
		if genErr != nil {
			return "", "", fmt.Errorf("failed to generate new key pair: %w", genErr)
		}

		// Ensure the keys directory exists
		keyDir := "keys"
		if mkdirErr := os.MkdirAll(keyDir, 0755); mkdirErr != nil {
			return "", "", fmt.Errorf("failed to create keys directory: %w", mkdirErr)
		}

		// Save the public key
		saveErr := os.WriteFile(publicKeyFile, []byte(newPublicKey), 0644)
		if saveErr != nil {
			return "", "", fmt.Errorf("failed to save public key: %w", saveErr)
		}

		// Save the private key (optional, if needed for encryption/decryption)
		privateKeyFile := fmt.Sprintf("keys/privk.key")
		savePrivateErr := os.WriteFile(privateKeyFile, []byte(newPrivateKey), 0600)
		if savePrivateErr != nil {
			return "", "", fmt.Errorf("failed to save private key: %w", savePrivateErr)
		}

		return newPublicKey, newPrivateKey, nil
	}

	// Return any other error
	return "", "", fmt.Errorf("error reading public key for current peer %s: %w", pb_err)
}

func StorePeerPublicKey(peerID, peerPublicKey string) error {
	keyDir := "keys"
	keyFile := fmt.Sprintf("%s/%s.pub", keyDir, peerID)

	if err := os.MkdirAll(keyDir, 0755); err != nil {
		return fmt.Errorf("failed to create keys directory: %w", err)
	}

	if err := os.WriteFile(keyFile, []byte(peerPublicKey), 0644); err != nil {
		return fmt.Errorf("failed to save public key for peer %s: %w", peerID, err)
	}

	return nil
}
