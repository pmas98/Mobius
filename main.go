package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"mobius/internal/network"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/libp2p/go-libp2p/core/host"
	libp2pnetwork "github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

const protocolID = "/file-share/1.0.0"

type FileShare struct {
	host     host.Host
	incoming string // Directory for incoming files
	outgoing string // Directory for outgoing files
	mu       sync.RWMutex
	peers    map[string]bool
}

func NewFileShare(h host.Host, incomingDir, outgoingDir string) *FileShare {
	fs := &FileShare{
		host:     h,
		incoming: incomingDir,
		outgoing: outgoingDir,
		peers:    make(map[string]bool),
	}

	// Ensure directories exist
	os.MkdirAll(incomingDir, 0755)
	os.MkdirAll(outgoingDir, 0755)

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

func (fs *FileShare) addPeer(peerID string) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	if peerID == fs.host.ID().String() {
		log.Printf("Skipping local peer %s\n", peerID)
		return // Avoid adding self to the peer list
	}

	fs.peers[peerID] = true
	log.Printf("Added peer: %s\n", peerID)
}

func (fs *FileShare) removePeer(peerID string) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	delete(fs.peers, peerID)
}

func main() {
	// Initialize bootstrap peers
	bootstrapPeers := []string{
		"/dnsaddr/bootstrap.libp2p.io/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
		"/dnsaddr/bootstrap.libp2p.io/p2p/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
		"/dnsaddr/bootstrap.libp2p.io/p2p/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
		"/dnsaddr/bootstrap.libp2p.io/p2p/QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt",
		"/dnsaddr/va1.bootstrap.libp2p.io/p2p/12D3KooWKnDdG3iXw9eTFijk3EWSunZcFi54Zka4wmtqtt6rPxc8",
		"/ip4/104.131.131.82/tcp/4001/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ",
		"/ip4/104.131.131.82/udp/4001/quic-v1/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ",
	}

	var multiaddrs []multiaddr.Multiaddr
	log.Println("Starting P2P node initialization...")

	for _, addr := range bootstrapPeers {
		log.Printf("Attempting to parse address: %s", addr)
		ma, err := multiaddr.NewMultiaddr(addr)
		if err != nil {
			log.Printf("Invalid bootstrap address %s: %v", addr, err)
			continue
		}
		log.Printf("Successfully parsed address: %s", addr)
		multiaddrs = append(multiaddrs, ma)
	}

	log.Println("Attempting to initialize the P2P node...")
	node, err := network.InitializeNode(multiaddrs)
	if err != nil {
		log.Fatalf("Failed to initialize P2P node: %v", err)
	}
	log.Println("P2P node initialized successfully.")
	defer node.Close()

	// Initialize file sharing
	fileShare := NewFileShare(node, "incoming", "")

	fmt.Println("P2P File Sharing Interactive Mode")
	fmt.Println("Available commands:")
	fmt.Println("  id              - Display peer ID")
	fmt.Println("  add [peer-id]   - Add a peer")
	fmt.Println("  remove [peer-id]- Remove a peer")
	fmt.Println("  share [path]    - Share a file")
	fmt.Println("  exit            - Exit the program")
	fmt.Println("  help            - Show this help message")

	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("\n> ")
		if !scanner.Scan() {
			break
		}

		input := scanner.Text()
		parts := strings.Fields(input)
		if len(parts) == 0 {
			continue
		}

		command := parts[0]

		switch command {
		case "id":
			fmt.Println("Peer ID:", node.ID().String())

		case "add":
			if len(parts) < 2 {
				fmt.Println("Usage: add [peer-id]")
				continue
			}
			fileShare.addPeer(parts[1])
			fmt.Printf("Added peer: %s\n", parts[1])

		case "remove":
			if len(parts) < 2 {
				fmt.Println("Usage: remove [peer-id]")
				continue
			}
			fileShare.removePeer(parts[1])
			fmt.Printf("Removed peer: %s\n", parts[1])

		case "share":
			if len(parts) < 2 {
				fmt.Println("Usage: share [file-path]")
				continue
			}
			filePath := strings.Join(parts[1:], " ") // Handle paths with spaces
			err := fileShare.shareFile(context.Background(), filePath)
			if err != nil {
				fmt.Printf("Error sharing file: %v\n", err)
			} else {
				fmt.Printf("File shared: %s\n", filePath)
			}

		case "help":
			fmt.Println("Available commands:")
			fmt.Println("  id              - Display peer ID")
			fmt.Println("  add [peer-id]   - Add a peer")
			fmt.Println("  remove [peer-id]- Remove a peer")
			fmt.Println("  share [path]    - Share a file")
			fmt.Println("  exit            - Exit the program")
			fmt.Println("  help            - Show this help message")

		case "exit":
			fmt.Println("Exiting...")
			return

		default:
			fmt.Printf("Unknown command: %s\nType 'help' for available commands\n", command)
		}
	}
}
