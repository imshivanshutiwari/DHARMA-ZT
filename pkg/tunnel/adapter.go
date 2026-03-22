package tunnel

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/dharma-zt/dharma-zt/pkg/core"
	"github.com/rs/zerolog"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type WireGuardAdapter struct {
	mu         sync.Mutex
	logger     zerolog.Logger
	ifaceName  string
	eventBus   *core.EventBus
	client     *wgctrl.Client
	port       int
	privateKey wgtypes.Key
}

func NewWireGuardAdapter(ifaceName string, eventBus *core.EventBus, logger zerolog.Logger) *WireGuardAdapter {
	return &WireGuardAdapter{
		ifaceName: ifaceName,
		eventBus:  eventBus,
		logger:    logger.With().Str("component", "tunnel").Logger(),
	}
}

func (a *WireGuardAdapter) Start(ctx context.Context, privateKey []byte, port int) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	var key wgtypes.Key
	copy(key[:], privateKey)
	a.privateKey = key
	a.port = port

	c, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("creating wg client: %w", err)
	}
	a.client = c

	link := &netlink.Wireguard{
		LinkAttrs: netlink.LinkAttrs{Name: a.ifaceName},
	}

	// Attempt to add link, ignore err if already exists, we will configure it anyway
	if err := netlink.LinkAdd(link); err != nil && err.Error() != "file exists" {
		a.logger.Warn().Err(err).Msg("Failed to create WireGuard interface via netlink, will try configuring existing")
	} else if err == nil {
		if err := netlink.LinkSetUp(link); err != nil {
			a.logger.Error().Err(err).Msg("Failed to set WireGuard interface up")
		}
	}

	cfg := wgtypes.Config{
		PrivateKey:   &a.privateKey,
		ListenPort:   &a.port,
		ReplacePeers: true, // Reset on start
	}

	if err := a.client.ConfigureDevice(a.ifaceName, cfg); err != nil {
		return fmt.Errorf("configuring wg device: %w", err)
	}

	a.logger.Info().Str("iface", a.ifaceName).Int("port", port).Msg("WireGuard tunnel configured")
	return nil
}

func (a *WireGuardAdapter) Stop() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.client != nil {
		if err := a.client.Close(); err != nil {
			return fmt.Errorf("closing wg client: %w", err)
		}
	}
	a.logger.Info().Msg("WireGuard adapter stopped")
	return nil
}

func (a *WireGuardAdapter) AddPeer(ctx context.Context, pubKey []byte, endpoint string, allowedIPs []net.IPNet) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	var pKey wgtypes.Key
	copy(pKey[:], pubKey)

	epAddr, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		return fmt.Errorf("resolving endpoint: %w", err)
	}

	keepAlive := 25 * time.Second

	peerCfg := wgtypes.PeerConfig{
		PublicKey:                   pKey,
		Endpoint:                    epAddr,
		AllowedIPs:                  allowedIPs,
		PersistentKeepaliveInterval: &keepAlive,
		ReplaceAllowedIPs:           true,
	}

	cfg := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peerCfg},
	}

	if err := a.client.ConfigureDevice(a.ifaceName, cfg); err != nil {
		return fmt.Errorf("configuring peer: %w", err)
	}

	a.logger.Info().Str("peer", pKey.String()).Msg("Added WireGuard peer")
	return nil
}

func (a *WireGuardAdapter) RemovePeer(ctx context.Context, pubKey []byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	var pKey wgtypes.Key
	copy(pKey[:], pubKey)

	peerCfg := wgtypes.PeerConfig{
		PublicKey: pKey,
		Remove:    true,
	}

	cfg := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peerCfg},
	}

	if err := a.client.ConfigureDevice(a.ifaceName, cfg); err != nil {
		return fmt.Errorf("removing peer: %w", err)
	}

	a.logger.Info().Str("peer", pKey.String()).Msg("Removed WireGuard peer")
	return nil
}

func (a *WireGuardAdapter) RotateKey(ctx context.Context, newPrivateKey []byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	var newKey wgtypes.Key
	copy(newKey[:], newPrivateKey)

	cfg := wgtypes.Config{
		PrivateKey: &newKey,
	}

	if err := a.client.ConfigureDevice(a.ifaceName, cfg); err != nil {
		return fmt.Errorf("rotating key: %w", err)
	}

	a.privateKey = newKey
	a.logger.Info().Msg("Rotated WireGuard key atomically")

	a.eventBus.Publish(ctx, core.Event{
		ID:        "key-rotation-" + time.Now().String(),
		Type:      core.EventKeyRotated,
		Timestamp: time.Now(),
		Payload:   "key rotated successfully",
	})

	return nil
}
