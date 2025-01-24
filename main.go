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
)

func main() {
	dht, node, err := network.InitializeNode()
	if err != nil {
		log.Fatalf("Failed to initialize P2P node: %v", err)
	}
	defer node.Close()

	fmt.Println("P2P node initialized successfully.")

	// Initialize file sharing
	cryptoMgr := crypto.NewCryptoManager()
	fileShare, err := file.NewFileManager(node, "incoming", "shared", cryptoMgr, dht)
	if err != nil {
		log.Fatalf("Failed to initialize file manager: %v", err)
	}

	fmt.Println("Mobius P2P File Sharing")
	fmt.Println("Available commands:")
	fmt.Println("  id              - Display your peer ID")
	fmt.Println("  add [peer-id]   - Add a peer")
	fmt.Println("  remove [peer-id]- Remove a peer")
	fmt.Println("  share [path]    - Share a file")
	fmt.Println("  listpeers       - List all peers with their keys")
	fmt.Println("  get [hash]      - Retrieve file metadata from the DHT")
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
			if len(parts) < 3 {
				fmt.Println("Usage: add [peer-id] [peer-name]")
				continue
			}
			peerID := parts[1]
			peerName := parts[2]
			err := fileShare.AddPeer(peerID, peerName)
			if err != nil {
				fmt.Printf("Error adding peer: %v\n", err)
			} else {
				fmt.Printf("Added peer: %s with name: %s\n", peerID, peerName)
			}

		case "remove":
			if len(parts) < 2 {
				fmt.Println("Usage: remove [peer-id]")
				continue
			}
			err := fileShare.RemovePeer(parts[1])
			if err != nil {
				fmt.Printf("Error removing peer: %v\n", err)
			} else {
				fmt.Printf("Removed peer: %s\n", parts[1])
			}

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
			metadata, err := fileShare.GetFileMetadataFromDHT(context.Background(), dht, hash)
			if err != nil {
				fmt.Printf("Error retrieving metadata for hash %s: %v\n", hash, err)
			} else {
				fmt.Printf("Metadata for hash %s:\n", hash)
				fmt.Printf("File Name: %s\n", metadata.Name)
				fmt.Printf("File Size: %d bytes\n", metadata.Size)
				// Print other fields in metadata as necessary
			}

		case "help":
			fmt.Println("Available commands:")
			fmt.Println("  id              - Display your peer ID")
			fmt.Println("  add [peer-id]   - Add a peer")
			fmt.Println("  remove [peer-id]- Remove a peer")
			fmt.Println("  share [path]    - Share a file")
			fmt.Println("  listpeers       - List all peers with their keys")
			fmt.Println("  get [hash]      - Retrieve file metadata from the DHT")
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
