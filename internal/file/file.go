package file

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"mobius/internal/crypto"
	"mobius/internal/utils"

	"github.com/google/uuid"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/host"
	libp2pnetwork "github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/mr-tron/base58/base58"
	mh "github.com/multiformats/go-multihash"
)

const (
	protocolID = "/mobius/1.0.0"
	rsaKeyBits = 2048
)

var (
	ErrNoPeers           = errors.New("no peers available to share with")
	ErrInvalidPeer       = errors.New("invalid peer ID")
	ErrLocalPeer         = errors.New("cannot add local peer")
	ErrNoKey             = errors.New("no decryption key found")
	ErrFileNotFound      = errors.New("file not found")
	ErrShareFailed       = errors.New("failed to share file with any peers")
	ErrInvalidDirectory  = errors.New("invalid directory path")
	ErrDatabaseOperation = errors.New("database operation error")
)

type FileManager struct {
	host        host.Host
	incomingDir string
	mu          sync.RWMutex
	peers       map[string]*peer.AddrInfo
	cryptoMgr   *crypto.CryptoManager
	keyMap      map[string]FileKeyInfo     // filename -> FileKeyInfo
	privateKeys map[string]*rsa.PrivateKey // peerID -> private key
	dht         *dht.IpfsDHT
	sharedDir   string
}

type FileKeyInfo struct {
	PeerID       string
	EncryptedKey string
}

type FileMetadata struct {
	Name     string
	Hash     string
	Size     int64
	SharerID string
}

func NewFileManager(h host.Host, incomingDir, sharedDir string, cryptoMgr *crypto.CryptoManager, dhtInstance *dht.IpfsDHT) (*FileManager, error) {
	if incomingDir == "" {
		return nil, ErrInvalidDirectory
	}

	// Create incoming directory
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
		sharedDir:   sharedDir,
		dht:         dhtInstance,
	}

	ownPeerID := h.ID().String()
	fm.privateKeys[ownPeerID] = privateKey
	fm.cryptoMgr.AddPeerPublicKey(ownPeerID, &privateKey.PublicKey)

	h.SetStreamHandler(protocolID, fm.handleIncomingFile)
	return fm, nil
}

func (fm *FileManager) handleIncomingFile(s libp2pnetwork.Stream) {
	defer s.Close()

	reader := bufio.NewReader(s)
	peerID := s.Conn().RemotePeer().String()
	log.Printf("Handling incoming file from peer: %s", peerID)

	// Read filename with timeout
	s.SetReadDeadline(time.Now().Add(600 * time.Second))
	filename, err := reader.ReadString('\n')
	if err != nil {
		log.Printf("Error reading filename: %v", err)
		return
	}
	filename = strings.TrimSpace(filename)

	// Read hash with timeout
	s.SetReadDeadline(time.Now().Add(600 * time.Second))
	receivedHash, err := reader.ReadString('\n')
	if err != nil {
		log.Printf("Error reading hash: %v", err)
		return
	}
	receivedHash = strings.TrimSpace(receivedHash)

	// Read symmetric key with timeout
	key := make([]byte, 32)
	s.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(reader, key); err != nil {
		log.Printf("Error reading symmetric key: %v", err)
		return
	}

	// Create temporary encrypted file
	tempEncryptedPath := filepath.Join(os.TempDir(), fmt.Sprintf("%s.%s.encrypted",
		filename, uuid.New().String()))
	tempEncFile, err := os.OpenFile(tempEncryptedPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Printf("Error creating temporary encrypted file: %v", err)
		return
	}
	defer os.Remove(tempEncryptedPath)
	defer tempEncFile.Close()

	// Set read deadline for file transfer
	s.SetReadDeadline(time.Now().Add(5 * time.Minute))

	// Copy encrypted data
	if _, err := io.Copy(tempEncFile, reader); err != nil {
		log.Printf("Error receiving encrypted file: %v", err)
		return
	}
	// Verify the hash of the encrypted file
	calculatedHash, _ := utils.GenerateFileHash(tempEncryptedPath)
	if calculatedHash != receivedHash {
		log.Printf("Hash mismatch for file %s. Expected: %s, Got: %s", filename, receivedHash, calculatedHash)
		return
	}
	log.Printf("Hash verification successful for file: %s", filename)

	// Store file metadata
	// if err = db.StoreFileMetadata(fm.db, filename, peerID, hex.EncodeToString(key), int(fileSize), "1.0"); err != nil {
	// 	log.Printf("Error storing file metadata: %v", err)
	// 	return
	// }

	// Prepare final path
	finalPath := filepath.Join(fm.incomingDir, filename)

	// Decrypt the file
	if err := fm.cryptoMgr.DecryptFile(tempEncryptedPath, finalPath, key); err != nil {
		log.Printf("Error decrypting file: %v", err)
		return
	}

	log.Printf("Successfully received, verified, decrypted, and stored file: %s from peer: %s",
		filename, peerID)
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
	log.Printf("Temporary encrypted file created at: %s", tempFile)

	// Generate symmetric key for file encryption
	key, err := fm.cryptoMgr.GenerateSymmetricKey()
	if err != nil {
		return fmt.Errorf("failed to generate symmetric key: %w", err)
	}
	log.Println("Symmetric key generated successfully")

	// Encrypt the file
	if err := fm.cryptoMgr.EncryptFile(filePath, tempFile, key); err != nil {
		return fmt.Errorf("failed to encrypt file: %w", err)
	}
	log.Printf("File encrypted and saved to: %s", tempFile)

	fileHash, err := utils.GenerateFileHash(tempFile)
	if err != nil {
		return fmt.Errorf("failed to generate file hash: %w", err)
	}
	log.Printf("Generated file hash: %s", fileHash)

	// Save a copy of the encrypted file to the incoming directory
	encryptedCopyPath := filepath.Join("shared", fmt.Sprintf("%s.enc", filename))
	if err := utils.CopyFile(tempFile, encryptedCopyPath); err != nil {
		return fmt.Errorf("failed to save encrypted file to incoming directory: %w", err)
	}
	log.Printf("Encrypted file saved to incoming directory: %s", encryptedCopyPath)

	store_err := fm.storePublicKeyInDHT(ctx, fm.dht, fileHash, FileMetadata{
		Name:     filename,
		Hash:     fileHash,
		Size:     0,
		SharerID: fm.host.ID().String(),
	})
	if store_err != nil {
		return fmt.Errorf("failed to store file metadata in DHT: %w", store_err)
	}
	return nil
}

func (fm *FileManager) shareFileWithPeer(ctx context.Context, peerID string, peerInfo *peer.AddrInfo, encryptedFilePath, filename string, key []byte, fileHash string) error {
	// Send the file without encrypting the key
	return fm.sendEncryptedFile(ctx, peerID, encryptedFilePath, filename, key, fileHash)
}

func (fm *FileManager) sendEncryptedFile(ctx context.Context, peerID, encryptedFilePath, filename string, key []byte, fileHash string) error {
	pid, err := peer.Decode(peerID)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidPeer, err)
	}
	log.Printf("Decoded peer ID: %s to PeerInfo", pid)

	stream, err := fm.host.NewStream(ctx, pid, protocolID)
	if err != nil {
		return fmt.Errorf("failed to open stream: %w", err)
	}
	defer stream.Close()
	log.Printf("Opened new stream with peer: %s", pid)

	// Send filename
	if _, err := fmt.Fprintf(stream, "%s\n", filename); err != nil {
		return fmt.Errorf("failed to send filename: %w", err)
	}
	log.Printf("Sent filename: %s to peer: %s", filename, pid)

	// Send file hash
	if _, err := fmt.Fprintf(stream, "%s\n", fileHash); err != nil {
		return fmt.Errorf("failed to send file hash: %w", err)
	}
	log.Printf("Sent file hash: %s to peer: %s", fileHash, pid)

	// Send raw symmetric key
	if _, err := stream.Write(key); err != nil {
		return fmt.Errorf("failed to send symmetric key: %w", err)
	}
	log.Println("Sent symmetric key successfully")

	// Open and send encrypted file
	file, err := os.Open(encryptedFilePath)
	if err != nil {
		return fmt.Errorf("failed to open encrypted file: %w", err)
	}
	defer file.Close()

	if _, err := io.Copy(stream, file); err != nil {
		return fmt.Errorf("failed to send encrypted file: %w", err)
	}
	log.Println("Encrypted file sent successfully")

	return nil
}

func (fm *FileManager) AddPeer(peerID, name string) error {
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

	// Add the peer to the database (address, last_seen, and name are handled)
	// db_err := fm.db.AddPeer(peerID, name)
	// if db_err != nil {
	// 	return fmt.Errorf("%w: %v", ErrDatabaseOperation, db_err)
	// }

	// Store the private key
	fm.privateKeys[peerID] = privateKey

	// Store the private key
	fm.privateKeys[peerID] = privateKey

	// Store the public key in crypto manager
	fm.cryptoMgr.AddPeerPublicKey(peerID, &privateKey.PublicKey)

	// Store peer info
	fm.peers[peerID] = &peer.AddrInfo{ID: pid}

	log.Printf("Added peer: %s", peerID)

	// Attempt to connect to the newly added peer immediately
	if err := fm.ConnectToPeer(peerID); err != nil {
		log.Printf("Failed to connect to peer %s: %v", peerID, err)
	} else {
		log.Printf("Successfully connected to peer %s", peerID)
	}

	return nil
}

// Generate RSA key pair
func generateRSAKeyPair() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// Compute the hash of the public key
func hashPublicKey(pub *rsa.PublicKey) (string, error) {
	keyBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}

	// Compute multihash of the public key
	hash := sha256.Sum256(keyBytes)
	hashedKey, err := mh.Encode(hash[:], mh.SHA2_256)
	if err != nil {
		return "", fmt.Errorf("failed to encode multihash: %w", err)
	}

	return base58.Encode(hashedKey), nil
}

func (fm *FileManager) storePublicKeyInDHT(ctx context.Context, dht *dht.IpfsDHT, hash string, metadata FileMetadata) error {
	key := fmt.Sprintf("/mobius/%s", hash)
	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		log.Fatalf("Failed to marshal metadata: %v", err)
	}
	// Store in DHT
	return dht.PutValue(ctx, key, metadataBytes)
}

func (fm *FileManager) GetFileMetadataFromDHT(ctx context.Context, dht *dht.IpfsDHT, hash string) (*FileMetadata, error) {
	key := fmt.Sprintf("/mobius/%s", hash)

	// Retrieve the metadata from DHT
	metadataBytes, err := dht.GetValue(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve metadata from DHT: %v", err)
	}

	// Unmarshal the bytes into the FileMetadata struct
	var metadata FileMetadata
	err = json.Unmarshal(metadataBytes, &metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %v", err)
	}

	return &metadata, nil
}

// ConnectToPeer attempts to connect to a given peer ID using the host's DHT.
func (fm *FileManager) ConnectToPeer(peerID string) error {
	pid, err := peer.Decode(peerID)
	if err != nil {
		return fmt.Errorf("failed to decode peer ID: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second) // Set a timeout for the connection attempt
	defer cancel()

	err = fm.host.Connect(ctx, peer.AddrInfo{ID: pid})
	if err != nil {
		return fmt.Errorf("failed to connect to peer %s: %w", peerID, err)
	}

	log.Printf("Connected to peer %s successfully", peerID)
	return nil
}

func (fm *FileManager) RemovePeer(peerID string) error {
	// Check if the peer exists before proceeding
	// _, err := fm.db.GetPeer(peerID)
	// if err != nil {
	// 	return fmt.Errorf("peer %s not found", peerID)
	// }

	// Lock the mutex before modifying in-memory data
	fm.mu.Lock()
	defer fm.mu.Unlock()

	// Remove the peer from in-memory data (maps)
	delete(fm.privateKeys, peerID)
	// fm.db.RemovePeer(peerID)
	fm.cryptoMgr.RemovePeerPublicKey(peerID)

	log.Printf("Removed peer: %s", peerID)
	return nil
}
