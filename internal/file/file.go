package file

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"

	"mobius/internal/crypto"
	"mobius/internal/db"
	"mobius/internal/utils"

	"github.com/ipfs/go-cid"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/host"
	libp2pnetwork "github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/routing"
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
	downloadDir string
	mu          sync.RWMutex
	peers       map[string]*peer.AddrInfo
	cryptoMgr   *crypto.CryptoManager
	keyMap      map[string]FileKeyInfo     // filename -> FileKeyInfo
	privateKeys map[string]*rsa.PrivateKey // peerID -> private key
	dht         *dht.IpfsDHT
	sharedDir   string
	db          *db.Database
}

type FileKeyInfo struct {
	PeerID       string
	EncryptedKey string
}

type FileMetadata struct {
	Name     string
	Hash     string
	Size     int64
	SharerID []string
}

// ProgressReader tracks download progress
type ProgressReader struct {
	Reader   io.Reader
	Total    int64
	Current  int64
	OnUpdate func(float64)
}

func NewFileManager(h host.Host, downloadDir, sharedDir string, cryptoMgr *crypto.CryptoManager, dhtInstance *dht.IpfsDHT, db *db.Database) (*FileManager, error) {
	if downloadDir == "" {
		return nil, ErrInvalidDirectory
	}

	// Create downloadDir directory
	if err := os.MkdirAll(downloadDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create incoming directory: %w", err)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	fm := &FileManager{
		host:        h,
		downloadDir: downloadDir,
		cryptoMgr:   cryptoMgr,
		peers:       make(map[string]*peer.AddrInfo),
		keyMap:      make(map[string]FileKeyInfo),
		privateKeys: make(map[string]*rsa.PrivateKey),
		sharedDir:   sharedDir,
		dht:         dhtInstance,
		db:          db,
	}

	ownPeerID := h.ID().String()
	fm.privateKeys[ownPeerID] = privateKey
	fm.cryptoMgr.AddPeerPublicKey(ownPeerID, &privateKey.PublicKey)

	h.SetStreamHandler(protocolID, fm.HandleFileRequest)
	return fm, nil
}

func (fm *FileManager) HandleFileRequest(stream libp2pnetwork.Stream) {
	defer stream.Close()

	// Read file hash from stream
	scanner := bufio.NewScanner(stream)
	scanner.Split(bufio.ScanLines)
	if !scanner.Scan() {
		log.Printf("Failed to read file hash")
		return
	}
	fileHash := scanner.Text()

	// Get file path
	filePath, err := fm.db.GetFilePath(fileHash)
	if err != nil {
		log.Printf("File not found: %v", err)
		return
	}

	// Open file for reading
	file, err := os.Open(filePath)
	if err != nil {
		log.Printf("Failed to open file: %v", err)
		return
	}
	defer file.Close()

	// Stream file to the requester
	if _, err = io.Copy(stream, file); err != nil {
		log.Printf("Failed to send file: %v", err)
	}
}

func (fm *FileManager) DownloadFile(ctx context.Context, fileHash cid.Cid) error {
	// Get file metadata from DHT
	metadata, err := fm.GetFileMetadataFromDHT(ctx, fm.dht, fileHash)
	if err != nil {
		return err
	}

	var downloadSuccess bool
	for _, sharerID := range metadata.SharerID {
		pid, err := peer.Decode(sharerID)
		if err != nil {
			log.Printf("Failed to decode sharer ID: %s, error: %v", sharerID, err)
			continue
		}

		// Attempt to establish a P2P connection
		stream, err := fm.host.NewStream(ctx, pid, protocolID)
		if err != nil {
			log.Printf("Failed to establish stream with peer: %s, error: %v", sharerID, err)
			continue
		}
		defer stream.Close()

		// Send file hash to request the specific file
		if _, err := fmt.Fprintf(stream, "%s\n", fileHash); err != nil {
			log.Printf("Failed to send file hash to peer: %s, error: %v", sharerID, err)
			continue
		}
		log.Printf("Sent file hash: %s to peer: %s", fileHash, sharerID)

		// Prepare local file with resume capability
		localFilePath := filepath.Join(fm.downloadDir, metadata.Name)
		file, err := os.OpenFile(localFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.Printf("Failed to open local file: %s, error: %v", localFilePath, err)
			continue
		}
		defer file.Close()

		// Get current file size for resuming
		currentSize, err := file.Seek(0, io.SeekEnd)
		if err != nil {
			log.Printf("Failed to seek in local file: %s, error: %v", localFilePath, err)
			continue
		}

		// Stream download with progress tracking
		progressReader := &ProgressReader{
			Reader:  stream,
			Total:   metadata.Size,
			Current: currentSize,
			OnUpdate: func(progress float64) {
				log.Printf("Download progress from peer %s: %.2f%%", sharerID, progress*100)
			},
		}

		if _, err := io.Copy(file, progressReader); err != nil {
			log.Printf("Failed to download file from peer: %s, error: %v", sharerID, err)

			continue
		}

		downloadSuccess = true
		break // Stop attempting after successful download
	}

	if !downloadSuccess {
		return fmt.Errorf("failed to download file from all peers")
	}

	// Add current peer ID to the SharerID list
	ownPeerID := fm.host.ID().String()
	if !utils.StringInSlice(ownPeerID, metadata.SharerID) {
		metadata.SharerID = append(metadata.SharerID, ownPeerID)
	}

	if err := fm.storeMetadataInDHT(ctx, fm.dht, fileHash, *metadata); err != nil {
		log.Printf("Failed to update metadata in DHT: %v", err)
		return err
	}

	log.Printf("Successfully downloaded file and updated sharer list: %s", metadata.Name)
	return nil
}

func (pr *ProgressReader) Read(p []byte) (int, error) {
	n, err := pr.Reader.Read(p)
	if n > 0 {
		pr.Current += int64(n)
		if pr.Total > 0 {
			progress := float64(pr.Current) / float64(pr.Total)
			pr.OnUpdate(progress)
		}
	}
	return n, err
}

func (fm *FileManager) ShareFile(ctx context.Context, filePath string) error {
	fileInfo, err := os.Stat(filePath)
	if os.IsNotExist(err) {
		return ErrFileNotFound
	}

	// Get base filename and file size
	filename := filepath.Base(filePath)
	fileSize := fileInfo.Size()

	fileCid, err := utils.GenerateFileCID(filePath)
	if err != nil {
		return fmt.Errorf("failed to generate file CID: %w", err)
	}

	// Store metadata with correct file size
	store_err := fm.storeMetadataInDHT(ctx, fm.dht, fileCid, FileMetadata{
		Name:     filename,
		Hash:     fileCid.String(),
		Size:     fileSize, // Store the ORIGINAL file size, not encrypted file size
		SharerID: []string{fm.host.ID().String()},
	})

	fm.db.AddFileMapping(fileCid.String(), filePath)
	if store_err != nil {
		return fmt.Errorf("failed to store file metadata in DHT: %w", store_err)
	}

	return nil
}

func (fm *FileManager) storeMetadataInDHT(ctx context.Context, dht *dht.IpfsDHT, hash cid.Cid, metadata FileMetadata) error {
	key := fmt.Sprintf("/mobius/%s", hash)
	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		log.Fatalf("Failed to marshal metadata: %v", err)
	}
	// Store in DHT
	return dht.PutValue(ctx, key, metadataBytes)
}

func (fm *FileManager) GetFileMetadataFromDHT(ctx context.Context, dht *dht.IpfsDHT, hash cid.Cid) (*FileMetadata, error) {
	key := fmt.Sprintf("/mobius/%s", hash)

	// Retrieve the metadata from DHT
	metadataBytes, err := dht.GetValue(ctx, key, routing.Expired)
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

func (fm *FileManager) shareFileWithPeer(ctx context.Context, peerID string, peerInfo *peer.AddrInfo, encryptedFilePath, filename string, key []byte, fileHash string) error {
	// Send the file without encrypting the key
	return fm.sendEncryptedFile(ctx, peerID, encryptedFilePath, filename, key, fileHash)
}

func (fm *FileManager) GetFilePath(ctx context.Context, dht *dht.IpfsDHT, hash string) (string, error) {
	key := fmt.Sprintf("/mobius/%s", hash)

	// Retrieve the metadata from DHT
	metadataBytes, err := dht.GetValue(ctx, key)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve metadata from DHT: %v", err)
	}

	// Unmarshal the bytes into the FileMetadata struct
	var metadata FileMetadata
	err = json.Unmarshal(metadataBytes, &metadata)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal metadata: %v", err)
	}

	filepath, file_err := fm.db.GetFilePath(hash)
	if file_err != nil {
		return "", fmt.Errorf("failed to retrieve file path: %v", file_err)
	}

	return filepath, nil
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
