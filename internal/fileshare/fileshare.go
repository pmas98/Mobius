package fileshare

import (
	"bufio"
	"context"
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
	host     host.Host
	incoming string // Directory for incoming files
	mu       sync.RWMutex
	peers    map[string]bool
}

func NewFileShare(h host.Host, incomingDir string) *FileShare {
	fs := &FileShare{
		host:     h,
		incoming: incomingDir,
		peers:    make(map[string]bool),
	}

	// Ensure directories exist
	os.MkdirAll(incomingDir, 0755)

	// Set stream handler for receiving files
	h.SetStreamHandler(protocolID, fs.handleIncomingFile)
	return fs
}

func (fs *FileShare) handleIncomingFile(s libp2pnetwork.Stream) {
	defer s.Close()

	reader := bufio.NewReader(s)

	// Read filename
	filename, err := reader.ReadString('\n')
	if err != nil {
		log.Printf("Error reading filename: %v", err)
		return
	}
	filename = filename[:len(filename)-1] // Remove newline

	// Create file in incoming directory
	filepath := filepath.Join(fs.incoming, filename)
	file, err := os.Create(filepath)
	if err != nil {
		log.Printf("Error creating file: %v", err)
		return
	}
	defer file.Close()

	// Copy file data
	_, err = io.Copy(file, reader)
	if err != nil {
		log.Printf("Error receiving file: %v", err)
		return
	}

	log.Printf("Received file: %s from peer: %s", filename, s.Conn().RemotePeer().String())
}

func (fs *FileShare) sendFileToPeer(ctx context.Context, peerID, filePath, filename string) error {
	// Convert string peer ID to PeerID type
	pid, err := peer.Decode(peerID)
	if err != nil {
		return fmt.Errorf("invalid peer ID: %w", err)
	}

	// Open stream to peer using the peer's ID, not our own
	stream, err := fs.host.NewStream(ctx, pid, protocolID)
	if err != nil {
		return fmt.Errorf("failed to open stream: %w", err)
	}
	defer stream.Close()

	// Send filename
	if _, err := fmt.Fprintf(stream, "%s\n", filename); err != nil {
		return fmt.Errorf("failed to send filename: %w", err)
	}

	// Open and send file
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	if _, err := io.Copy(stream, file); err != nil {
		return fmt.Errorf("failed to send file: %w", err)
	}

	return nil
}

func (fs *FileShare) shareFile(ctx context.Context, filePath string) error {
	// Verify file exists
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

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
			if err := fs.sendFileToPeer(ctx, pid, filePath, filename); err != nil {
				log.Printf("Error sharing file with peer %s: %v", pid, err)
				errChan <- err
			}
		}(peerID)
	}

	wg.Wait()
	close(errChan)

	// Check if all transfers failed
	var errors []error
	for err := range errChan {
		errors = append(errors, err)
	}

	if len(errors) == len(fs.peers) {
		return fmt.Errorf("failed to share file with any peers: %v", errors[0])
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
