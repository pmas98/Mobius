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

	"github.com/multiformats/go-multiaddr"
)

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
	cryptoMgr := crypto.NewCryptoManager()
	fileShare, _ := file.NewFileManager(node, "incoming", cryptoMgr)

	fmt.Println("Mobius P2P File Sharing")
	fmt.Println("Available commands:")
	fmt.Println("  id              - Display your peer ID")
	fmt.Println("  add [peer-id]   - Add a peer")
	fmt.Println("  remove [peer-id]- Remove a peer")
	fmt.Println("  share [path]    - Share a file")
	fmt.Println("  listpeers       - List all peers with their keys")
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
			fileShare.AddPeer(parts[1])
			fmt.Printf("Added peer: %s\n", parts[1])

		case "remove":
			if len(parts) < 2 {
				fmt.Println("Usage: remove [peer-id]")
				continue
			}
			fileShare.RemovePeer(parts[1])
			fmt.Printf("Removed peer: %s\n", parts[1])

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

		case "listpeers":
			peers := fileShare.ListPeers()
			if len(peers) == 0 {
				fmt.Println("No peers available.")
			} else {
				fmt.Println("Peers and associated keys:")
				for peerID, key := range peers {
					fmt.Printf("Peer ID: %s, Key: %s\n", peerID, key)
				}
			}

		case "help":
			fmt.Println("Available commands:")
			fmt.Println("  id              - Display your peer ID")
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
