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
	"github.com/libp2p/go-libp2p/core/crypto"
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

func GetOwnKeysFromDisk() (crypto.PubKey, crypto.PrivKey, error) {
	publicKeyFile := "keys/pubk.pem"
	privateKeyFile := "keys/privk.pem"

	fmt.Println("Attempting to read public key from:", publicKeyFile)
	fmt.Println("Attempting to read private key from:", privateKeyFile)

	// Attempt to read the key from disk
	publicKey, pbErr := os.ReadFile(publicKeyFile)
	privateKey, pvErr := os.ReadFile(privateKeyFile)

	if pbErr == nil && pvErr == nil {
		fmt.Println("Keys found on disk, unmarshalling...")
		block_pub, _ := pem.Decode(publicKey)
		block_priv, _ := pem.Decode(privateKey)

		publicKeyBytes, _ := x509.MarshalPKIXPublicKey(block_pub.Bytes)
		pubkey, _ := crypto.UnmarshalPublicKey(publicKeyBytes)

		privateKeyBytes, _ := x509.MarshalPKCS8PrivateKey(block_priv.Bytes)
		privkey, _ := crypto.UnmarshalPrivateKey(privateKeyBytes)

		fmt.Println("Successfully unmarshalled keys")
		return pubkey, privkey, nil
	}

	if os.IsNotExist(pbErr) && os.IsNotExist(pvErr) {
		fmt.Println("Keys do not exist, generating new key pair...")
		// Key does not exist, generate a new one
		newPublicKey, newPrivateKey, genErr := GenerateNewKeyPair()
		if genErr != nil {
			fmt.Println("Failed to generate new key pair:", genErr)
			return nil, nil, fmt.Errorf("failed to generate new key pair: %w", genErr)
		}

		// Ensure the keys directory exists
		keyDir := "keys"
		fmt.Println("Creating keys directory:", keyDir)
		if mkdirErr := os.MkdirAll(keyDir, 0755); mkdirErr != nil {
			fmt.Println("Failed to create keys directory:", mkdirErr)
			return nil, nil, fmt.Errorf("failed to create keys directory: %w", mkdirErr)
		}

		// Save the public key
		fmt.Println("Saving public key to:", publicKeyFile)
		saveErr := os.WriteFile(publicKeyFile, []byte(newPublicKey), 0644)
		if saveErr != nil {
			fmt.Println("Failed to save public key:", saveErr)
			return nil, nil, fmt.Errorf("failed to save public key: %w", saveErr)
		}

		// Save the private key
		fmt.Println("Saving private key to:", privateKeyFile)
		savePrivateErr := os.WriteFile(privateKeyFile, []byte(newPrivateKey), 0600)
		if savePrivateErr != nil {
			fmt.Println("Failed to save private key:", savePrivateErr)
			return nil, nil, fmt.Errorf("failed to save private key: %w", savePrivateErr)
		}

		privateKeyUnmarshalled, _ := crypto.UnmarshalPrivateKey([]byte(newPrivateKey))
		publicKeyUnmarshalled, _ := crypto.UnmarshalPublicKey([]byte(newPublicKey))
		fmt.Println("Successfully generated and saved new key pair")
		return publicKeyUnmarshalled, privateKeyUnmarshalled, nil
	}

	// Return any other error
	fmt.Println("Error reading keys from disk:", pbErr, pvErr)
	return nil, nil, fmt.Errorf("error reading keys from disk: %v, %v", pbErr, pvErr)
}

func StorePeerPublicKey(peerID, peerPublicKey string) error {
	keyDir := "keys"
	keyFile := fmt.Sprintf("%s/%s.pem", keyDir, peerID)

	if err := os.MkdirAll(keyDir, 0755); err != nil {
		return fmt.Errorf("failed to create keys directory: %w", err)
	}

	if err := os.WriteFile(keyFile, []byte(peerPublicKey), 0644); err != nil {
		return fmt.Errorf("failed to save public key for peer %s: %w", peerID, err)
	}

	return nil
}
