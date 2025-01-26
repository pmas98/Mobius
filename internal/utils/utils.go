package utils

import (
	"crypto/rand"
	"crypto/rsa"
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
func GenerateNewKeyPair() ([]byte, []byte, error) {
	// Generate RSA key pair with 2048-bit key length
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	// Marshal private key to PEM
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// Marshal public key to PEM
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encode public key: %w", err)
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return publicKeyPEM, privateKeyPEM, nil
}

func GetOwnKeysFromDisk() (crypto.PubKey, crypto.PrivKey, error) {
	publicKeyFile := "keys/pubk.pem"
	privateKeyFile := "keys/privk.pem"

	// Read key files
	publicKey, pbErr := os.ReadFile(publicKeyFile)
	privateKey, pvErr := os.ReadFile(privateKeyFile)

	// Keys exist, attempt to decode
	if pbErr == nil && pvErr == nil {
		block_pub, _ := pem.Decode(publicKey)
		block_priv, _ := pem.Decode(privateKey)
		if block_pub == nil || block_priv == nil {
			return nil, nil, fmt.Errorf("failed to decode keys")
		}

		pubKeyTyped, err := crypto.UnmarshalPublicKey(block_pub.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to unmarshal public key: %v", err)
		}

		privKeyBytes, err := crypto.UnmarshalPrivateKey(block_priv.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to marshal private key: %v", err)
		}

		return pubKeyTyped, privKeyBytes, nil
	}

	// Keys don't exist, generate new pair
	if os.IsNotExist(pbErr) && os.IsNotExist(pvErr) {
		// Create keys directory
		keyDir := "keys"
		if mkdirErr := os.MkdirAll(keyDir, 0755); mkdirErr != nil {
			return nil, nil, fmt.Errorf("failed to create keys directory: %w", mkdirErr)
		}

		// Generate new key pair
		newPublicKey, newPrivateKey, genErr := GenerateNewKeyPair()
		if genErr != nil {
			return nil, nil, fmt.Errorf("failed to generate new key pair: %w", genErr)
		}

		// Save public key
		if saveErr := os.WriteFile(publicKeyFile, newPublicKey, 0644); saveErr != nil {
			return nil, nil, fmt.Errorf("failed to save public key: %w", saveErr)
		}

		// Save private key
		if savePrivateErr := os.WriteFile(privateKeyFile, newPrivateKey, 0600); savePrivateErr != nil {
			return nil, nil, fmt.Errorf("failed to save private key: %w", savePrivateErr)
		}

		// Unmarshal newly generated keys
		privateKeyUnmarshalled, privUnmarshalErr := crypto.UnmarshalRsaPrivateKey(newPrivateKey)
		if privUnmarshalErr != nil {
			return nil, nil, fmt.Errorf("failed to unmarshal new private key: %w", privUnmarshalErr)
		}

		pubKeyTyped, err := crypto.UnmarshalRsaPublicKey(newPublicKey)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to unmarshal public key: %v", err)
		}

		return pubKeyTyped, privateKeyUnmarshalled, nil
	}

	// Return any other error
	return nil, nil, fmt.Errorf("error reading keys from disk: %v, %v", pbErr, pvErr)
}

func StorePeerPublicKey(peerID string, pubKey crypto.PubKey) error {
	keyDir := "keys"
	keyFile := fmt.Sprintf("%s/%s.pem", keyDir, peerID)

	fmt.Println("Got here")

	pubKeyBytes, err := crypto.MarshalPublicKey(pubKey)
	if err != nil {
		fmt.Printf("Got error %s", err)
	}

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}

	// Write to file
	publicKeyPEM := pem.EncodeToMemory(pemBlock)
	fmt.Printf("The public key is %s", publicKeyPEM)
	if saveErr := os.WriteFile(keyFile, publicKeyPEM, 0644); saveErr != nil {
		fmt.Println(saveErr)
	}
	return nil
}
