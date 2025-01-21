package file

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/libp2p/go-libp2p/core/host"
	libp2pnetwork "github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"

	"mobius/internal/crypto"
)

const (
	protocolID = "/mobius/1.0.0"
	rsaKeyBits = 2048
)

var (
	ErrNoPeers          = errors.New("no peers available to share with")
	ErrInvalidPeer      = errors.New("invalid peer ID")
	ErrLocalPeer        = errors.New("cannot add local peer")
	ErrNoKey            = errors.New("no decryption key found")
	ErrFileNotFound     = errors.New("file not found")
	ErrShareFailed      = errors.New("failed to share file with any peers")
	ErrInvalidDirectory = errors.New("invalid directory path")
)

type FileManager struct {
	host        host.Host
	incomingDir string
	mu          sync.RWMutex
	peers       map[string]*peer.AddrInfo
	cryptoMgr   *crypto.CryptoManager
	keyMap      map[string]FileKeyInfo     // filename -> FileKeyInfo
	privateKeys map[string]*rsa.PrivateKey // peerID -> private key
}

type FileKeyInfo struct {
	PeerID       string
	EncryptedKey string
}

func NewFileManager(h host.Host, incomingDir string, cryptoMgr *crypto.CryptoManager) (*FileManager, error) {
	if incomingDir == "" {
		return nil, ErrInvalidDirectory
	}

	// Ensure incoming directory exists
	if err := os.MkdirAll(incomingDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create incoming directory: %w", err)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	fm := &FileManager{
		host:        h,
		incomingDir: incomingDir,
		cryptoMgr:   cryptoMgr,
		peers:       make(map[string]*peer.AddrInfo),
		keyMap:      make(map[string]FileKeyInfo),
		privateKeys: make(map[string]*rsa.PrivateKey),
	}

	// Store our own private key using our peer ID
	ownPeerID := h.ID().String()
	fm.privateKeys[ownPeerID] = privateKey

	// Store our own public key in the crypto manager
	fm.cryptoMgr.AddPeerPublicKey(ownPeerID, &privateKey.PublicKey)

	// Set stream handler for receiving files
	h.SetStreamHandler(protocolID, fm.handleIncomingFile)
	return fm, nil
}

func (fm *FileManager) handleIncomingFile(s libp2pnetwork.Stream) {
	defer s.Close()

	reader := bufio.NewReader(s)

	// Read filename
	filename, err := reader.ReadString('\n')
	if err != nil {
		log.Printf("Error reading filename: %v", err)
		return
	}
	filename = strings.TrimSpace(filename)

	// Read raw symmetric key
	key := make([]byte, 32) // Assuming AES-256
	if _, err := io.ReadFull(reader, key); err != nil {
		log.Printf("Error reading symmetric key: %v", err)
		return
	}

	// Create temporary file for encrypted data
	tempEncryptedPath := filepath.Join(os.TempDir(), fmt.Sprintf("%s.encrypted", filename))
	tempEncFile, err := os.OpenFile(tempEncryptedPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Printf("Error creating temporary encrypted file: %v", err)
		return
	}

	// Copy encrypted data to temporary file
	if _, err := io.Copy(tempEncFile, reader); err != nil {
		log.Printf("Error receiving encrypted file: %v", err)
		tempEncFile.Close()
		os.Remove(tempEncryptedPath)
		return
	}
	tempEncFile.Close()

	// Create final output file path
	finalPath := filepath.Join(fm.incomingDir, filename)

	// Decrypt the file directly
	if err := fm.cryptoMgr.DecryptFile(tempEncryptedPath, finalPath, key); err != nil {
		log.Printf("Error decrypting file: %v", err)
		os.Remove(tempEncryptedPath)
		return
	}

	// Clean up temporary encrypted file
	os.Remove(tempEncryptedPath)

	log.Printf("Successfully received and decrypted file: %s from peer: %s", filename, s.Conn().RemotePeer().String())
}

func (fm *FileManager) ListPeers() map[string]string {
	fm.mu.RLock()
	defer fm.mu.RUnlock()

	peerKeyMap := make(map[string]string)
	for peerID := range fm.peers {
		peerKeyMap[peerID] = fm.keyMap[peerID].EncryptedKey
	}
	return peerKeyMap
}

func (fm *FileManager) ShareFile(ctx context.Context, filePath string) error {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return ErrFileNotFound
	}

	// Get base filename
	filename := filepath.Base(filePath)

	// Create temporary file for encrypted data
	tempFile := filepath.Join(os.TempDir(), fmt.Sprintf("%s.encrypted", filename))
	defer os.Remove(tempFile) // Clean up temp file after sharing

	// Generate symmetric key for file encryption
	key, err := fm.cryptoMgr.GenerateSymmetricKey()
	if err != nil {
		return fmt.Errorf("failed to generate symmetric key: %w", err)
	}

	// Encrypt the file
	if err := fm.cryptoMgr.EncryptFile(filePath, tempFile, key); err != nil {
		return fmt.Errorf("failed to encrypt file: %w", err)
	}

	// Save a copy of the encrypted file to the incoming directory
	encryptedCopyPath := filepath.Join("outgoing", fmt.Sprintf("%s.enc", filename))
	if err := copyFile(tempFile, encryptedCopyPath); err != nil {
		return fmt.Errorf("failed to save encrypted file to incoming directory: %w", err)
	}
	log.Printf("Encrypted file saved to incoming directory: %s", encryptedCopyPath)

	fm.mu.RLock()
	peerCount := len(fm.peers)
	fm.mu.RUnlock()

	if peerCount == 0 {
		return ErrNoPeers
	}

	var (
		wg           sync.WaitGroup
		errChan      = make(chan error, peerCount)
		successCount int32
		successMu    sync.Mutex
	)

	// Share with all peers concurrently
	fm.mu.RLock()
	for peerID, peerInfo := range fm.peers {
		wg.Add(1)
		go func(pid string, pi *peer.AddrInfo) {
			defer wg.Done()

			if err := fm.shareFileWithPeer(ctx, pid, pi, tempFile, filename, key); err != nil {
				errChan <- fmt.Errorf("failed to share with peer %s: %w", pid, err)
				return
			}

			successMu.Lock()
			successCount++
			successMu.Unlock()
		}(peerID, peerInfo)
	}
	fm.mu.RUnlock()

	// Wait for all sharing operations to complete
	wg.Wait()
	close(errChan)

	if successCount == 0 {
		var errors []string
		for err := range errChan {
			errors = append(errors, err.Error())
		}
		return fmt.Errorf("%w: %s", ErrShareFailed, strings.Join(errors, "; "))
	}

	log.Printf("Successfully shared file with %d peers", successCount)
	return nil
}

// Helper function to copy a file
func copyFile(src, dst string) error {
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
func (fm *FileManager) shareFileWithPeer(ctx context.Context, peerID string, peerInfo *peer.AddrInfo, encryptedFilePath, filename string, key []byte) error {
	// Send the file without encrypting the key
	return fm.sendEncryptedFile(ctx, peerID, encryptedFilePath, filename, key)
}

func (fm *FileManager) sendEncryptedFile(ctx context.Context, peerID, encryptedFilePath, filename string, key []byte) error {
	pid, err := peer.Decode(peerID)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidPeer, err)
	}

	stream, err := fm.host.NewStream(ctx, pid, protocolID)
	if err != nil {
		return fmt.Errorf("failed to open stream: %w", err)
	}
	defer stream.Close()

	// Send filename
	if _, err := fmt.Fprintf(stream, "%s\n", filename); err != nil {
		return fmt.Errorf("failed to send filename: %w", err)
	}

	// Send raw symmetric key
	if _, err := stream.Write(key); err != nil {
		return fmt.Errorf("failed to send symmetric key: %w", err)
	}

	// Open and send encrypted file
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

func (fm *FileManager) AddPeer(peerID string) error {
	if peerID == fm.host.ID().String() {
		return ErrLocalPeer
	}

	// Decode peer ID to validate format
	pid, err := peer.Decode(peerID)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidPeer, err)
	}

	// Generate a new RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		return fmt.Errorf("failed to generate RSA key pair: %w", err)
	}

	fm.mu.Lock()
	defer fm.mu.Unlock()

	// Store the private key
	fm.privateKeys[peerID] = privateKey

	// Store the public key in crypto manager
	fm.cryptoMgr.AddPeerPublicKey(peerID, &privateKey.PublicKey)

	// Store peer info
	fm.peers[peerID] = &peer.AddrInfo{ID: pid}

	log.Printf("Added peer: %s", peerID)
	return nil
}

func (fm *FileManager) RemovePeer(peerID string) {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	delete(fm.peers, peerID)
	delete(fm.privateKeys, peerID)
}
