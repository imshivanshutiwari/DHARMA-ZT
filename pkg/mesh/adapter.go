package mesh

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/dharma-zt/dharma-zt/pkg/core"
	"github.com/libp2p/go-libp2p"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/discovery/mdns"
	"github.com/rs/zerolog"
)

type Libp2pAdapter struct {
	mu          sync.RWMutex
	host        host.Host
	pubsub      *pubsub.PubSub
	mdns        mdns.Service
	eventBus    *core.EventBus
	logger      zerolog.Logger
	emconActive bool
	peers       map[peer.ID]*core.PeerStatus
	alertTopic  *pubsub.Topic
}

type discoveryNotifee struct {
	h      host.Host
	logger zerolog.Logger
}

func (n *discoveryNotifee) HandlePeerFound(pi peer.AddrInfo) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := n.h.Connect(ctx, pi); err != nil {
		n.logger.Debug().Err(err).Str("peer", pi.ID.String()).Msg("Failed to connect to discovered peer")
	} else {
		n.logger.Info().Str("peer", pi.ID.String()).Msg("Connected to discovered peer")
	}
}

func NewLibp2pAdapter(port int, privKey crypto.PrivKey, eventBus *core.EventBus, logger zerolog.Logger) (*Libp2pAdapter, error) {
	h, err := libp2p.New(
		libp2p.ListenAddrStrings(fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", port)),
		libp2p.Identity(privKey),
		libp2p.NATPortMap(), // Attempt to open ports
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create libp2p host: %w", err)
	}

	ps, err := pubsub.NewGossipSub(context.Background(), h)
	if err != nil {
		return nil, fmt.Errorf("failed to create gossipsub: %w", err)
	}

	return &Libp2pAdapter{
		host:     h,
		pubsub:   ps,
		eventBus: eventBus,
		logger:   logger.With().Str("component", "mesh").Logger(),
		peers:    make(map[peer.ID]*core.PeerStatus),
	}, nil
}

func (a *Libp2pAdapter) Start(ctx context.Context) error {
	a.logger.Info().Str("id", a.host.ID().String()).Msg("Starting Libp2p adapter")

	// Setup mDNS discovery
	a.mdns = mdns.NewMdnsService(a.host, "_dharma._tcp", &discoveryNotifee{h: a.host, logger: a.logger})
	if err := a.mdns.Start(); err != nil {
		a.logger.Warn().Err(err).Msg("Failed to start mDNS discovery")
	}

	// Setup PubSub topics
	alertTopic, err := a.pubsub.Join("dharma/alerts/v1")
	if err != nil {
		return fmt.Errorf("joining alert topic: %w", err)
	}
	a.alertTopic = alertTopic

	alertSub, err := a.alertTopic.Subscribe()
	if err != nil {
		return fmt.Errorf("subscribing to alerts: %w", err)
	}

	go a.handleAlerts(ctx, alertSub)

	a.logger.Info().Msg("Libp2p adapter started")
	return nil
}

func (a *Libp2pAdapter) Stop() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	var errs []error
	if a.mdns != nil {
		if err := a.mdns.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if a.host != nil {
		if err := a.host.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors stopping libp2p: %v", errs)
	}
	a.logger.Info().Msg("Libp2p adapter stopped")
	return nil
}

func (a *Libp2pAdapter) GetPeers() []peer.ID {
	return a.host.Network().Peers()
}

func (a *Libp2pAdapter) GetPeerStatus(id peer.ID) (core.PeerStatus, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if status, ok := a.peers[id]; ok {
		return *status, nil
	}
	return core.PeerStatus{}, fmt.Errorf("peer not found")
}

func (a *Libp2pAdapter) SetEMCON(active bool) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.emconActive = active
	if active {
		a.logger.Warn().Msg("EMCON activated - stopping active discovery and gossip")
		if a.mdns != nil {
			if err := a.mdns.Close(); err != nil {
				a.logger.Error().Err(err).Msg("Failed to close mDNS service")
			}
		}
	} else {
		a.logger.Info().Msg("EMCON deactivated - resuming normal operations")
		a.mdns = mdns.NewMdnsService(a.host, "_dharma._tcp", &discoveryNotifee{h: a.host, logger: a.logger})
		if err := a.mdns.Start(); err != nil {
			a.logger.Error().Err(err).Msg("Failed to start mDNS discovery")
			return err
		}
	}

	return nil
}

func (a *Libp2pAdapter) BroadcastAlert(ctx context.Context, alertType string, data []byte) error {
	if a.emconActive {
		a.logger.Warn().Msg("EMCON active: suppressing broadcast alert")
		return nil
	}

	if a.alertTopic == nil {
		return fmt.Errorf("alert topic not initialized")
	}

	payload := append([]byte(alertType+":"), data...)
	if err := a.alertTopic.Publish(ctx, payload); err != nil {
		return fmt.Errorf("publishing alert: %w", err)
	}
	return nil
}

func (a *Libp2pAdapter) handleAlerts(ctx context.Context, sub *pubsub.Subscription) {
	for {
		msg, err := sub.Next(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			a.logger.Error().Err(err).Msg("Error reading from alert subscription")
			continue
		}

		// Don't process our own messages
		if msg.ReceivedFrom == a.host.ID() {
			continue
		}

		a.logger.Warn().Str("from", msg.ReceivedFrom.String()).Str("payload", string(msg.Data)).Msg("Received alert via pubsub")

		a.eventBus.Publish(ctx, core.Event{
			ID:        "alert-" + time.Now().String(),
			Type:      core.EventLockdown, // Or other based on parsing
			Timestamp: time.Now(),
			Payload:   string(msg.Data),
		})
	}
}
