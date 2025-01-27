package file

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
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
	crypt "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	libp2pnetwork "github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/routing"
)

const (
	fileProtocolID       = "/mobius/1.0.0"
	messagingProtocolID  = "/mobius/messaging/1.0.0"
	publickKeyProtocolID = "/mobius/publickey/1.0.0"
	connectionProtocolID = "/mobius/connection/1.0.0"
	rsaKeyBits           = 2048
	ChunkSize            = 1024 * 1024 // 1MB
	Parallelism          = 4
)

type ChunkRequest struct {
	ChunkIndex int
	Data       []byte
	Err        error
}

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
	host                 host.Host
	downloadDir          string
	mu                   sync.RWMutex
	peers                map[string]*peer.AddrInfo
	cryptoMgr            *crypto.CryptoManager
	keyMap               map[string]FileKeyInfo // filename -> FileKeyInfo
	dht                  *dht.IpfsDHT
	sharedDir            string
	db                   *db.Database
	activeMessageStreams map[string]libp2pnetwork.Stream // peerID -> active stream
	messageStreamMutex   sync.Mutex
	privateKey           crypt.PrivKey
	publicKey            any
	context              context.Context
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

func NewFileManager(ctx context.Context, h host.Host, downloadDir, sharedDir string, cryptoMgr *crypto.CryptoManager, dhtInstance *dht.IpfsDHT, db *db.Database) (*FileManager, error) {
	if downloadDir == "" {
		return nil, ErrInvalidDirectory
	}

	// Create downloadDir directory
	if err := os.MkdirAll(downloadDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create download directory: %w", err)
	}
	ownPublicKey, ownPrivateKey, key_err := utils.GetOwnKeysFromDisk()
	if key_err != nil {
		return nil, fmt.Errorf("no public key found: %w", key_err)
	}

	fm := &FileManager{
		host:                 h,
		downloadDir:          downloadDir,
		cryptoMgr:            cryptoMgr,
		peers:                make(map[string]*peer.AddrInfo),
		keyMap:               make(map[string]FileKeyInfo),
		sharedDir:            sharedDir,
		dht:                  dhtInstance,
		db:                   db,
		activeMessageStreams: make(map[string]libp2pnetwork.Stream),
		privateKey:           ownPrivateKey,
		publicKey:            ownPublicKey,
		context:              ctx,
	}

	h.SetStreamHandler(fileProtocolID, fm.HandleFileRequest)
	h.SetStreamHandler(messagingProtocolID, fm.HandleMessageRequest)
	h.SetStreamHandler(publickKeyProtocolID, fm.handleKeyExchange)
	h.SetStreamHandler(connectionProtocolID, fm.handleConnection)
	return fm, nil
}

func (fm *FileManager) handleConnection(stream libp2pnetwork.Stream) {
	defer stream.Close()

	// Read peer ID from the stream
	buffer := make([]byte, 4096)
	n, err := stream.Read(buffer)
	if err != nil {
		log.Printf("Failed to read peer ID: %v", err)
		return
	}

	peerID := string(buffer[:n])
	log.Printf("Received connection request from peer: %s", peerID)

	pid, err := peer.Decode(peerID)
	if err != nil {
		log.Printf("Invalid peer ID: %s, error: %v", peerID, err)
		return
	}

	messageStream, err := fm.host.NewStream(fm.context, pid, messagingProtocolID)
	if err != nil {
		log.Printf("Failed to create message stream with %s: %v", peerID, err)
		return
	}

	fm.activeMessageStreams[peerID] = messageStream

	log.Printf("Connection established with peer %s", peerID)
}

// InitiateConnection handles the initial connection setup and key exchange with a peer.
func (fm *FileManager) InitiateConnection(ctx context.Context, peerID string) error {
	log.Printf("Initiating connection with peer: %s", peerID)

	pid, err := peer.Decode(peerID)
	if err != nil {
		log.Printf("Invalid peer ID: %s, error: %v", peerID, err)
		return fmt.Errorf("invalid peer ID: %w", err)
	}
	log.Printf("Decoded peer ID: %s", pid)

	// Establish a connection with the peer
	connection_stream, err := fm.host.NewStream(ctx, pid, connectionProtocolID)
	if err != nil {
		log.Printf("Failed to establish connection with peer: %s, error: %v", peerID, err)
		return fmt.Errorf("failed to establish stream: %w", err)
	}
	defer connection_stream.Close()

	if _, err := connection_stream.Write([]byte(fm.host.ID().String())); err != nil {
		return fmt.Errorf("failed to send ID: %w", err)
	}

	key_exchange_stream, err := fm.host.NewStream(ctx, pid, publickKeyProtocolID)
	if err != nil {
		log.Printf("Failed to establish key exchange stream with peer: %s, error: %v", peerID, err)
		return fmt.Errorf("failed to establish stream: %w", err)
	}
	log.Printf("Established key exchange stream with peer: %s", peerID)

	message_stream, err := fm.host.NewStream(ctx, pid, messagingProtocolID)
	if err != nil {
		log.Printf("Failed to establish message stream with peer: %s, error: %v", peerID, err)
		key_exchange_stream.Close()
		return fmt.Errorf("failed to establish stream: %w", err)
	}
	log.Printf("Established message stream with peer: %s", peerID)

	// Perform key exchange
	err = fm.ExchangeKeys(key_exchange_stream)
	if err != nil {
		log.Printf("Key exchange failed with peer: %s, error: %v", peerID, err)
		message_stream.Close()
		key_exchange_stream.Close()
		return fmt.Errorf("key exchange failed: %w", err)
	}
	log.Printf("Key exchange successful with peer: %s", peerID)

	// Store the message stream for the peer
	fm.activeMessageStreams[peerID] = message_stream
	log.Printf("Stored message stream for peer: %s", peerID)

	log.Printf("Connection and key exchange established with peer %s.", peerID)

	return nil
}

// SendMessage encrypts and sends a message to a specified peer.
func (fm *FileManager) SendMessage(ctx context.Context, recipientPeerID string, message string) error {
	stream, _ := fm.GetStreamFromPeerID(recipientPeerID)

	peerPublicKey, err := fm.cryptoMgr.GetPeerPublicKey(recipientPeerID)
	if err != nil {
		return fmt.Errorf("recipient's public key not found: %w", err)
	}

	encryptedMessage, err := fm.cryptoMgr.Encrypt([]byte(message), peerPublicKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt message: %w", err)
	}

	_, err = stream.Write(encryptedMessage)
	if err != nil {
		return fmt.Errorf("failed to send message: %w", err)
	}

	log.Printf("Message sent to peer %s successfully.", recipientPeerID)
	return nil
}

func (fm *FileManager) CloseConnection(pid string, stream libp2pnetwork.Stream) {
	// Get the peer ID from the stream
	peerID := stream.Conn().RemotePeer().String()
	peer_stream := fm.activeMessageStreams[peerID]
	// Log the peer ID
	log.Printf("Closing connection with peer: %s", peerID)

	if err := peer_stream.Close(); err != nil {
		log.Printf("Failed to close stream: %v", err)
	} else {
		log.Println("Stream closed successfully.")
	}
}

// ExchangeKeys exchanges public keys with a peer upon connection.
func (fm *FileManager) ExchangeKeys(stream libp2pnetwork.Stream) error {
	defer stream.Close()

	publicKeyRaw, err := x509.MarshalPKIXPublicKey(fm.publicKey)
	if err != nil {
		return fmt.Errorf("failed to get raw public key: %w", err)
	}

	if _, err := stream.Write(publicKeyRaw); err != nil {
		return fmt.Errorf("failed to send public key: %w", err)
	}

	// Read peer's public key
	buffer := make([]byte, 4096)
	n, err := stream.Read(buffer)
	if err != nil {
		return fmt.Errorf("failed to read peer's public key: %w", err)
	}

	publicKeyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: buffer[:n],
	})

	block, _ := pem.Decode([]byte(publicKeyPem))
	if block == nil {
		log.Printf("Failed to decode PEM block")

	}

	peerID := stream.Conn().RemotePeer().String()
	utils.StorePeerPublicKey(peerID, publicKeyPem)

	log.Printf("Public key exchange completed with peer %s.", peerID)
	return nil
}

func (fm *FileManager) handleKeyExchange(stream libp2pnetwork.Stream) {
	defer stream.Close()

	// Read peer's public key
	buffer := make([]byte, 4096)
	n, err := stream.Read(buffer)
	if err != nil {
		log.Printf("Failed to read peer's public key: %v", err)
		return
	}

	publicKeyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: buffer[:n],
	})

	fmt.Printf("Public key: %v\n", string(publicKeyPem))

	block, _ := pem.Decode([]byte(publicKeyPem))
	if block == nil {
		log.Printf("Failed to decode PEM block")
		return
	}

	peerID := stream.Conn().RemotePeer().String()
	log.Printf("Received %d bytes of public key from peer %s", n, peerID)
	utils.StorePeerPublicKey(peerID, publicKeyPem)

	ownPublicKeyBytes, err := x509.MarshalPKIXPublicKey(fm.publicKey)
	if err != nil {
		log.Printf("Failed to get raw public key: %v", err)
		return
	}

	if _, err := stream.Write(ownPublicKeyBytes); err != nil {
		log.Printf("Failed to send public key: %v", err)
		return
	}

	log.Printf("Public key exchange completed with peer %s.", peerID)
}

// HandleMessageRequest processes incoming messages from a peer.
func (fm *FileManager) HandleMessageRequest(stream libp2pnetwork.Stream) {
	peerID := stream.Conn().RemotePeer().String()

	// Handle the messages in a separate goroutine
	go func() {
		for {
			var encryptedMessage []byte
			buffer := make([]byte, 4096)
			n, err := stream.Read(buffer)
			if err == io.EOF {
				log.Printf("Connection closed by peer %s.", peerID)
				return
			}
			if err != nil {
				log.Printf("Error reading message from peer %s: %v", peerID, err)
				return
			}
			encryptedMessage = append(encryptedMessage, buffer[:n]...)

			decryptedMessage, err := fm.cryptoMgr.Decrypt(encryptedMessage)
			if err != nil {
				log.Printf("Failed to decrypt message from %s: %v", peerID, err)
				return
			}

			log.Printf("Received message from %s: %s.", peerID, string(decryptedMessage))
		}
	}()
}

func (fm *FileManager) GetStreamFromPeerID(peerID string) (libp2pnetwork.Stream, error) {
	peer, exists := fm.activeMessageStreams[peerID]
	if !exists {
		return nil, ErrInvalidPeer
	}

	return peer, nil
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

	// Get file size
	fileInfo, err := file.Stat()
	if err != nil {
		log.Printf("Failed to stat file: %v", err)
		return
	}

	totalChunks := int((fileInfo.Size() + ChunkSize - 1) / ChunkSize)
	buffer := make([]byte, ChunkSize)
	for i := 0; i < totalChunks; i++ {
		file.Seek(int64(i*ChunkSize), io.SeekStart)
		n, err := file.Read(buffer)
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Printf("Error reading chunk: %v", err)
			break
		}
		if n > 0 {
			_, writeErr := stream.Write(buffer[:n])
			if writeErr != nil {
				log.Printf("Error writing chunk to stream: %v", writeErr)
				break
			}
		}
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
		stream, err := fm.host.NewStream(ctx, pid, fileProtocolID)
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

		buffer := make([]byte, ChunkSize)
		totalChunks := int((metadata.Size + ChunkSize - 1) / ChunkSize)
		for i := 0; i < totalChunks; i++ {
			n, readErr := stream.Read(buffer)
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				log.Printf("Error reading chunk: %v", readErr)
				break
			}
			if n > 0 {
				file.Seek(int64(i*ChunkSize), io.SeekStart)
				file.Write(buffer[:n])

				// Print progress
				fmt.Printf("Progress: %.2f%%\n", (float64(i+1)/float64(totalChunks))*100)
			}
		}

		downloadSuccess = true
		break
	}

	if !downloadSuccess {
		return fmt.Errorf("failed to download file from all peers")
	}

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

	stream, err := fm.host.NewStream(ctx, pid, fileProtocolID)
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
