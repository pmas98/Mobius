package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"mobius/internal/crypto"
	"mobius/internal/file"
	"mobius/internal/network"
	"os"
	"strings"
	"time"

	"github.com/ipfs/go-cid"
)

func main() {
	dbPath := "db.sqlite3"
	dht, node, db, err := network.InitializeNode(dbPath)
	if err != nil {
		log.Fatalf("Failed to initialize P2P node: %v", err)
	}
	defer node.Close()

	fmt.Println("P2P node initialized successfully.")

	// Initialize file sharing
	cryptoMgr := crypto.NewCryptoManager()
	fileShare, err := file.NewFileManager(node, "incoming", "shared", cryptoMgr, dht, db)
	if err != nil {
		log.Fatalf("Failed to initialize file manager: %v", err)
	}

	fmt.Println("Mobius P2P File Sharing")
	fmt.Println("Available commands:")
	fmt.Println("  id                - Display your peer ID")
	fmt.Println("  share [path]      - Share a file")
	fmt.Println("  get [hash]        - Retrieve file metadata from the DHT")
	fmt.Println("  download [hash]   - Download a file using its hash")
	fmt.Println("  help              - Show this help message")
	fmt.Println("  exit              - Exit the program")

	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	go func() {
		for range ticker.C {
			db.ValidateFileMappings()
		}
	}()

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

		case "share":
			if len(parts) < 2 {
				fmt.Println("Usage: share [file-path]")
				continue
			}
			filePath := strings.Join(parts[1:], " ") // Handle paths with spaces
			err := fileShare.ShareFile(context.Background(), filePath)
			if err != nil {
				fmt.Printf("Error sharing file: %v\n", err)
			} else {
				fmt.Printf("File shared: %s\n", filePath)
			}

		case "get":
			if len(parts) < 2 {
				fmt.Println("Usage: get [hash]")
				continue
			}
			hash := parts[1]
			cid, err := cid.Decode(hash)
			if err != nil {
				fmt.Printf("Error decoding hash %s: %v\n", hash, err)
				continue
			}
			metadata, err := fileShare.GetFileMetadataFromDHT(context.Background(), dht, cid)
			if err != nil {
				fmt.Printf("Error retrieving metadata for hash %s: %v\n", hash, err)
			} else {
				fmt.Printf("Metadata for hash %s:\n", hash)
				fmt.Printf("File Name: %s\n", metadata.Name)
				fmt.Printf("File Size: %d bytes\n", metadata.Size)
				fmt.Printf("Sharer Identity: %s\n", metadata.SharerID)
			}

		case "download":
			if len(parts) < 2 {
				fmt.Println("Usage: download [hash]")
				continue
			}
			hash := parts[1]
			cid, err := cid.Decode(hash)
			if err != nil {
				fmt.Printf("Error decoding hash %s: %v\n", hash, err)
				continue
			}
			err = fileShare.DownloadFile(context.Background(), cid)
			if err != nil {
				fmt.Printf("Error downloading file with hash %s: %v\n", hash, err)
			} else {
				fmt.Printf("File downloaded successfully for hash: %s\n", hash)
			}

		case "help":
			fmt.Println("Available commands:")
			fmt.Println("  id                - Display your peer ID")
			fmt.Println("  share [path]      - Share a file")
			fmt.Println("  get [hash]        - Retrieve file metadata from the DHT")
			fmt.Println("  download [hash]   - Download a file using its hash")
			fmt.Println("  help              - Show this help message")
			fmt.Println("  exit              - Exit the program")

		case "exit":
			fmt.Println("Exiting...")
			return

		default:
			fmt.Printf("Unknown command: %s\nType 'help' for available commands\n", command)
		}
	}
}
