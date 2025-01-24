package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	record "github.com/libp2p/go-libp2p-record"
)

type FileMetadataValidator struct{}
type FileMetadata struct {
	Name         string `json:"name"`
	Size         int64  `json:"size"`
	FileType     string `json:"file_type"`
	UploadedBy   string `json:"uploaded_by"`
	UploadDate   string `json:"upload_date"`
	LastModified string `json:"last_modified"`
}

func (v *FileMetadataValidator) Select(key string, values [][]byte) (int, error) {
	// Implement selection logic if needed, for now, just return the first value
	return 0, nil
}

func (v *FileMetadataValidator) Validate(key string, value []byte) error {
	// Ensure the key has the correct format
	if len(key) < 10 {
		return fmt.Errorf("invalid key: too short")
	}

	// Ensure the value (metadata) is not empty
	if len(value) == 0 {
		return fmt.Errorf("invalid value: empty")
	}

	// Try to unmarshal the value as JSON to ensure it's valid metadata
	var metadata FileMetadata
	if err := json.Unmarshal(value, &metadata); err != nil {
		return fmt.Errorf("invalid metadata format: %v", err)
	}

	// Additional validation logic (e.g., check file size, name, etc.)
	if metadata.Size <= 0 {
		return fmt.Errorf("invalid file size")
	}
	return nil
}

func createBootstrapPeer() error {
	// Create a basic libp2p host
	host, err := libp2p.New()
	if err != nil {
		return fmt.Errorf("failed to create libp2p node: %w", err)
	}
	defer host.Close()

	// Set up a DHT with a custom validator for the "mobius" namespace
	validatorMap := record.NamespacedValidator{
		"mobius": &FileMetadataValidator{}, // Use the custom file metadata validator
	}

	// Creating DHT instance
	_, dth_err := dht.New(context.Background(), host, dht.Mode(dht.ModeServer), dht.Validator(validatorMap), dht.ProtocolPrefix("/mobius"))
	if dth_err != nil {
		return fmt.Errorf("failed to create DHT: %w", err)
	}

	// Get the multiaddress of this peer
	multiaddr := host.Addrs()[0] // Just using the first address
	peerID := host.ID()

	// Print out the peer ID and multiaddress
	fmt.Printf("Bootstrap peer ID: %s\n", peerID)
	fmt.Printf("Bootstrap peer multiaddress: %s/p2p/%s\n", multiaddr, peerID)

	// Wait indefinitely
	select {}
}

func main() {
	if err := createBootstrapPeer(); err != nil {
		log.Fatalf("Error creating bootstrap node: %v", err)
	}
}
