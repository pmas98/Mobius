package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	record "github.com/libp2p/go-libp2p-record"
)

// Function to get public IP of the EC2 instance
func getPublicIP() (string, error) {
	// Request public IP from AWS metadata API
	resp, err := http.Get("http://169.254.169.254/latest/meta-data/public-ipv4")
	if err != nil {
		return "", fmt.Errorf("failed to get public IP: %w", err)
	}
	defer resp.Body.Close()

	// Read the response body
	ip, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	return string(ip), nil
}

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
	return 0, nil
}

func (v *FileMetadataValidator) Validate(key string, value []byte) error {
	if len(key) < 10 {
		return fmt.Errorf("invalid key: too short")
	}
	if len(value) == 0 {
		return fmt.Errorf("invalid value: empty")
	}

	var metadata FileMetadata
	if err := json.Unmarshal(value, &metadata); err != nil {
		return fmt.Errorf("invalid metadata format: %v", err)
	}

	if metadata.Size <= 0 {
		return fmt.Errorf("invalid file size")
	}
	return nil
}

func createBootstrapPeer() error {
	// Get the public IP of the EC2 instance
	ipAddress, err := getPublicIP()
	if err != nil {
		return fmt.Errorf("failed to get public IP: %w", err)
	}

	// Create a basic libp2p host
	host, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/0.0.0.0/tcp/4000"))
	if err != nil {
		return fmt.Errorf("failed to create libp2p node: %w", err)
	}
	defer host.Close()

	// Set up a DHT with a custom validator for the "mobius" namespace
	validatorMap := record.NamespacedValidator{
		"mobius": &FileMetadataValidator{},
	}

	// Creating DHT instance
	_, dth_err := dht.New(context.Background(), host, dht.Mode(dht.ModeServer), dht.Validator(validatorMap), dht.ProtocolPrefix("/mobius"))
	if dth_err != nil {
		return fmt.Errorf("failed to create DHT: %w", err)
	}

	// Create the multiaddress using the EC2 public IP
	multiaddr := fmt.Sprintf("/ip4/%s/tcp/4000", ipAddress)
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
