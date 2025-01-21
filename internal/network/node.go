package network

import (
	"context"
	"fmt"
	"time"

	"github.com/ipfs/go-log/v2"
	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/discovery/routing"
	"github.com/multiformats/go-multiaddr"
)

var logger = log.Logger("p2p-discovery")

// InitializeNode initializes a libp2p node with Kademlia DHT
func InitializeNode(bootstrapPeers []multiaddr.Multiaddr) (host.Host, error) {
	// Create a new libp2p host with explicit listen addresses
	h, err := libp2p.New(
		libp2p.ListenAddrStrings(
			"/ip4/0.0.0.0/tcp/0",
			"/ip6/::/tcp/0",
		),
		libp2p.EnableRelay(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create libp2p host: %w", err)
	}

	logger.Info("Node started with addresses:", h.Addrs())
	logger.Info("Peer ID:", h.ID())

	// Create a new DHT client mode instance
	ctx := context.Background()
	kademliaDHT, err := dht.New(ctx, h,
		dht.Mode(dht.ModeClient),
		dht.BootstrapPeers(convertToAddrInfo(bootstrapPeers)...),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create DHT: %w", err)
	}

	// Bootstrap the DHT
	logger.Info("Bootstrapping the DHT")
	if err := kademliaDHT.Bootstrap(ctx); err != nil {
		return nil, fmt.Errorf("failed to bootstrap DHT: %w", err)
	}

	// Connect to bootstrap peers
	if err := connectToBootstrapPeers(ctx, h, bootstrapPeers); err != nil {
		logger.Warning("Failed to connect to some bootstrap peers:", err)
	}

	// Start peer discovery
	routingDiscovery := routing.NewRoutingDiscovery(kademliaDHT)
	go startDiscovery(ctx, h, routingDiscovery)

	return h, nil
}

// connectToBootstrapPeers attempts to connect to the bootstrap peers
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
		rendezvousString  = "p2p-file-sharing"
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
