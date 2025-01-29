package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/ipfs/go-cid"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/multiformats/go-multihash"
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

// GenerateNewKeyPair generates an RSA key pair and returns PEM-encoded public and private keys.
func GenerateNewKeyPair() (string, string, error) {
	// Generate 2048-bit RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate key pair: %w", err)
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
		return "", "", fmt.Errorf("failed to encode public key: %w", err)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return string(publicKeyPEM), string(privateKeyPEM), nil
}

func GetPrivateKeyBlock() (*pem.Block, error) {
	// Read the private key from the file
	keyData, err := os.ReadFile("keys/privk.pem")
	if err != nil {
		fmt.Println(err)
	}

	// Parse the PEM-encoded private key
	block, _ := pem.Decode(keyData)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		fmt.Println("invalid private key format")
	}

	return block, nil
}

func GetOwnKeysFromDisk() (any, crypto.PrivKey, error) {
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

		// Parse private key
		privkey, err_priv := x509.ParsePKCS1PrivateKey(block_priv.Bytes)
		if err_priv != nil {
			return nil, nil, fmt.Errorf("failed to parse private key: %v", err_priv)
		}

		// Unmarshal public key
		pubKeyTyped, err := x509.ParsePKIXPublicKey(block_pub.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to unmarshal public key: %v", err)
		}

		// Unmarshal private key
		privKeyBytes := x509.MarshalPKCS1PrivateKey(privkey)
		privKeyTyped, err := crypto.UnmarshalRsaPrivateKey(privKeyBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to unmarshal private key: %v", err)
		}

		return pubKeyTyped, privKeyTyped, nil
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
		if saveErr := os.WriteFile(publicKeyFile, []byte(newPublicKey), 0644); saveErr != nil {
			return nil, nil, fmt.Errorf("failed to save public key: %w", saveErr)
		}

		// Save private key
		if savePrivateErr := os.WriteFile(privateKeyFile, []byte(newPrivateKey), 0600); savePrivateErr != nil {
			return nil, nil, fmt.Errorf("failed to save private key: %w", savePrivateErr)
		}

		// Parse newly generated keys
		privateKeyUnmarshalled, privUnmarshalErr := x509.ParsePKCS1PrivateKey([]byte(newPrivateKey))
		if privUnmarshalErr != nil {
			return nil, nil, fmt.Errorf("failed to unmarshal new private key: %w", privUnmarshalErr)
		}

		pubKeyTyped, err := crypto.UnmarshalRsaPublicKey([]byte(newPublicKey))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to unmarshal public key: %v", err)
		}

		privKeyBytes := x509.MarshalPKCS1PrivateKey(privateKeyUnmarshalled)
		privKeyTyped, err := crypto.UnmarshalRsaPrivateKey(privKeyBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to unmarshal private key: %v", err)
		}

		return pubKeyTyped, privKeyTyped, nil
	}

	// Return any other error
	return nil, nil, fmt.Errorf("error reading keys from disk: %v, %v", pbErr, pvErr)
}
func StorePeerPublicKey(peerID string, pubKey []byte) error {
	keyDir := "keys"
	keyFile := fmt.Sprintf("%s/%s.pem", keyDir, peerID)

	if saveErr := os.WriteFile(keyFile, pubKey, 0644); saveErr != nil {
		fmt.Println(saveErr)
	}
	return nil
}
