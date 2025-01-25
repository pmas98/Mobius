package fileshare

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"

	"github.com/libp2p/go-libp2p/core/host"
	libp2pnetwork "github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

const protocolID = "/mobius/1.0.0"

type FileShare struct {
	host           host.Host
	download       string
	mu             sync.RWMutex
	peers          map[string]bool
	peerPublicKeys map[string]*rsa.PublicKey // Changed from keys to peerPublicKeys for clarity
}

func NewFileShare(h host.Host, downloadDir string) *FileShare {
	fs := &FileShare{
		host:           h,
		download:       downloadDir,
		peers:          make(map[string]bool),
		peerPublicKeys: make(map[string]*rsa.PublicKey), // Initialize the peerPublicKeys map
	}

	// Ensure directories exist
	os.MkdirAll(downloadDir, 0755)

	// Set stream handler for receiving files
	h.SetStreamHandler(protocolID, fs.handledownloadFile)
	return fs
}

func (fs *FileShare) getPeerPublicKey(peerID string) (*rsa.PublicKey, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	publicKey, exists := fs.peerPublicKeys[peerID] // Fixed map name
	if !exists {
		return nil, fmt.Errorf("public key for peer %s not found", peerID)
	}

	return publicKey, nil
}

func generateSymmetricKey() ([]byte, error) {
	key := make([]byte, 32) // AES-256
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func encryptKeyForPeer(publicKey *rsa.PublicKey, key []byte) (string, error) {
	encryptedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, key, nil)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(encryptedKey), nil
}

func encryptFile(inputPath, outputPath string, key []byte) error {
	file, err := os.Open(inputPath)
	if err != nil {
		return err
	}
	defer file.Close()

	output, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer output.Close()

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	writer := &cipher.StreamWriter{S: stream, W: output}

	// Write IV to the beginning of the file
	if _, err := output.Write(iv); err != nil {
		return err
	}

	if _, err := io.Copy(writer, file); err != nil {
		return err
	}

	return nil
}

func (fs *FileShare) handledownloadFile(s libp2pnetwork.Stream) {
	defer s.Close()

	reader := bufio.NewReader(s)

	// Read filename first
	filename, err := reader.ReadString('\n')
	if err != nil {
		log.Printf("Error reading filename: %v", err)
		return
	}
	filename = filename[:len(filename)-1] // Remove newline

	// Read encrypted key
	encryptedKey, err := reader.ReadString('\n')
	if err != nil {
		log.Printf("Error reading encrypted key: %v", err)
		return
	}
	encryptedKey = encryptedKey[:len(encryptedKey)-1] // Remove newline

	// Create file in download directory
	filepath := filepath.Join(fs.download, filename)
	file, err := os.Create(filepath)
	if err != nil {
		log.Printf("Error creating file: %v", err)
		return
	}
	defer file.Close()

	// Copy encrypted file data
	_, err = io.Copy(file, reader)
	if err != nil {
		log.Printf("Error receiving file: %v", err)
		return
	}

	log.Printf("Received encrypted file: %s from peer: %s", filename, s.Conn().RemotePeer().String())
}

func (fs *FileShare) shareFile(ctx context.Context, filePath string) error {
	// Generate symmetric key
	key, err := generateSymmetricKey()
	if err != nil {
		return fmt.Errorf("failed to generate symmetric key: %w", err)
	}

	// Encrypt file
	encryptedFilePath := filePath + ".enc"
	if err := encryptFile(filePath, encryptedFilePath, key); err != nil {
		return fmt.Errorf("failed to encrypt file: %w", err)
	}
	defer os.Remove(encryptedFilePath)

	// Get filename
	filename := filepath.Base(filePath)

	// Share with all peers
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	if len(fs.peers) == 0 {
		return fmt.Errorf("no peers available to share with")
	}

	var wg sync.WaitGroup
	errChan := make(chan error, len(fs.peers))

	for peerID := range fs.peers {
		wg.Add(1)
		go func(pid string) {
			defer wg.Done()

			publicKey, err := fs.getPeerPublicKey(pid)
			if err != nil {
				errChan <- fmt.Errorf("failed to get public key for peer %s: %w", pid, err)
				return
			}

			// Encrypt the symmetric key for the peer
			encryptedKey, err := encryptKeyForPeer(publicKey, key)
			if err != nil {
				errChan <- fmt.Errorf("failed to encrypt key for peer %s: %w", pid, err)
				return
			}

			// Send encrypted file and key
			if err := fs.sendEncryptedFile(ctx, pid, encryptedFilePath, filename, encryptedKey); err != nil {
				errChan <- fmt.Errorf("failed to share file with peer %s: %w", pid, err)
			}
		}(peerID)
	}

	wg.Wait()
	close(errChan)

	var errors []error
	for err := range errChan {
		errors = append(errors, err)
	}

	if len(errors) == len(fs.peers) {
		return fmt.Errorf("failed to share file with any peers: %v", errors[0])
	}

	return nil
}

func (fs *FileShare) sendEncryptedFile(ctx context.Context, peerID, encryptedFilePath, filename, encryptedKey string) error {
	// Convert string peer ID to PeerID type
	pid, err := peer.Decode(peerID)
	if err != nil {
		return fmt.Errorf("invalid peer ID: %w", err)
	}

	// Open stream to peer
	stream, err := fs.host.NewStream(ctx, pid, protocolID)
	if err != nil {
		return fmt.Errorf("failed to open stream: %w", err)
	}
	defer stream.Close()

	// Send filename first
	if _, err := fmt.Fprintf(stream, "%s\n", filename); err != nil {
		return fmt.Errorf("failed to send filename: %w", err)
	}

	// Send encrypted key
	if _, err := fmt.Fprintf(stream, "%s\n", encryptedKey); err != nil {
		return fmt.Errorf("failed to send encrypted key: %w", err)
	}

	// Send encrypted file
	file, err := os.Open(encryptedFilePath)
	if err != nil {
		return fmt.Errorf("failed to open encrypted file: %w", err)
	}
	defer file.Close()

	if _, err := io.Copy(stream, file); err != nil {
		return fmt.Errorf("failed to send encrypted file: %w", err)
	}

	return nil
}

func (fs *FileShare) AddPeer(peerID string) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	if peerID == fs.host.ID().String() {
		log.Printf("Skipping local peer %s\n", peerID)
		return // Avoid adding self to the peer list
	}

	fs.peers[peerID] = true
	log.Printf("Added peer: %s\n", peerID)
}

func (fs *FileShare) RemovePeer(peerID string) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	delete(fs.peers, peerID)
}
