package network

import (
	"context"
	"encoding/json"
	"fmt"
	"mobius/internal/db"
	"mobius/internal/utils"
	"time"

	"github.com/ipfs/go-log/v2"
	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	record "github.com/libp2p/go-libp2p-record"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/discovery/routing"

	"github.com/multiformats/go-multiaddr"
)

var logger = log.Logger("p2p-discovery")

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

	return nil
}

func InitializeNode(dbpath string) (*dht.IpfsDHT, host.Host, *db.Database, context.Context, error) {
	ctx := context.Background()

	// Step 1: Set up database connection
	db, err := db.InitializeDB(dbpath)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to initialize database: %w", err)
	}

	_, privKeyStr, err := utils.GetOwnKeysFromDisk()
	if err != nil {
		fmt.Println("Following error occured while getting keys from disk: ", err)
		panic(err)
	}
	privKey := privKeyStr
	h, err := libp2p.New(
		libp2p.Identity(privKey),
		libp2p.DefaultTransports,
		libp2p.ListenAddrStrings("/ip4/0.0.0.0/tcp/4000"), // Listen on all interfaces, port 4000
		libp2p.EnableNATService(),
	)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to create libp2p host: %w", err)
	}

	// Set up a DHT with a custom validator for the "file" namespace
	validatorMap := record.NamespacedValidator{
		"mobius": &FileMetadataValidator{}, // Use the custom file metadata validator
	}
	idht, d_err := dht.New(ctx, h, dht.Mode(dht.ModeClient), dht.Validator(validatorMap), dht.ProtocolPrefix("/mobius"))
	if d_err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to create DHT: %w", d_err)
	}

	// Bootstrap peers
	bootstrapPeers := []string{
		"/ip4/34.233.134.60/tcp/4000/p2p/12D3KooWEsP5m8VHQtRRciGXPaJqv2hyRD2TC9KKg7QAEBPTm3T3",
	}
	var addrInfos []peer.AddrInfo
	for _, addr := range bootstrapPeers {
		maddr, err := multiaddr.NewMultiaddr(addr)
		if err != nil {
			logger.Fatalf("Failed to parse multiaddress: %v", err)
		}
		pinfo, err := peer.AddrInfoFromString(maddr.String())
		if err != nil {
			logger.Fatalf("Failed to get peer info from multiaddress: %v", err)
		}
		addrInfos = append(addrInfos, *pinfo)
	}

	// Connect to bootstrap peers
	for _, addrInfo := range addrInfos {
		if err := h.Connect(ctx, addrInfo); err != nil {
			logger.Fatalf("Failed to connect to bootstrap peer %v: %v", addrInfo.ID, err)
		} else {
			fmt.Printf("Connected to bootstrap peer %v\n", addrInfo.ID)
		}
	}

	logger.Info("Node started with addresses:", h.Addrs())
	logger.Info("Peer ID:", h.ID())

	routingDiscovery := routing.NewRoutingDiscovery(idht)
	go startDiscovery(ctx, h, routingDiscovery)

	return idht, h, db, ctx, nil
}
func connectToBootstrapPeers(ctx context.Context, h host.Host, bootstrapPeers []multiaddr.Multiaddr) error {
	peerInfos := convertToAddrInfo(bootstrapPeers)

	var lastErr error
	for _, peerInfo := range peerInfos {
		if peerInfo.ID == h.ID() {
			continue
		}

		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()

		if err := h.Connect(ctx, peerInfo); err != nil {
			logger.Warning("Failed to connect to bootstrap peer:", peerInfo, "error:", err)
			lastErr = err
			continue
		}
		logger.Info("Connected to bootstrap peer:", peerInfo)
	}
	return lastErr
}

// convertToAddrInfo converts multiaddrs to peer.AddrInfo
func convertToAddrInfo(addrs []multiaddr.Multiaddr) []peer.AddrInfo {
	var peerInfos []peer.AddrInfo
	for _, addr := range addrs {
		info, err := peer.AddrInfoFromP2pAddr(addr)
		if err != nil {
			logger.Warning("Failed to convert multiaddr to peer info:", err)
			continue
		}
		peerInfos = append(peerInfos, *info)
	}
	return peerInfos
}

// startDiscovery implements continuous peer discovery
func startDiscovery(ctx context.Context, h host.Host, routingDiscovery *routing.RoutingDiscovery) {
	// Define discovery parameters
	const (
		discoveryInterval = 1 * time.Minute
		rendezvousString  = "mobius-p2p-file-sharing"
	)

	// Continuously advertise and discover peers
	for {
		// Advertise ourselves
		ttl, err := routingDiscovery.Advertise(ctx, rendezvousString)
		if err != nil {
			logger.Warning("Failed to advertise:", err)
		} else {
			logger.Info("Successfully advertised with TTL:", ttl)
		}

		// Find peers
		peers, err := routingDiscovery.FindPeers(ctx, rendezvousString)
		if err != nil {
			logger.Warning("Failed to find peers:", err)
			time.Sleep(discoveryInterval)
			continue
		}

		// Try to connect to discovered peers
		for peer := range peers {
			if peer.ID == h.ID() {
				continue
			}

			ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			if err := h.Connect(ctx, peer); err != nil {
				logger.Debug("Failed to connect to peer:", peer.ID, "error:", err)
			} else {
				logger.Info("Successfully connected to peer:", peer.ID)
			}
			cancel()
		}

		time.Sleep(discoveryInterval)
	}
}
