package utils

import (
	"crypto/sha256"
	"encoding/gob"
	"fmt"
	"io"
	"os"
	"strings"

	libp2pnetwork "github.com/libp2p/go-libp2p/core/network"
	"github.com/mr-tron/base58"
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
