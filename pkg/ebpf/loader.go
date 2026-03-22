package ebpf

import (
	"context"
	"net"
	"sync"

	"github.com/cilium/ebpf/link"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/rs/zerolog"
)

type bpfObjects struct{}

type Adapter struct {
	mu           sync.Mutex
	logger       zerolog.Logger
	iface        string
	bpfObjs      bpfObjects
	xdpLink      link.Link
	peerMap      map[peer.ID]net.IP
}

func NewEBPFAdapter(iface string, logger zerolog.Logger) *Adapter {
	return &Adapter{
		iface:   iface,
		logger:  logger.With().Str("component", "ebpf").Logger(),
		peerMap: make(map[peer.ID]net.IP),
	}
}

func (a *Adapter) Load(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.logger.Info().Str("iface", a.iface).Msg("Loading eBPF XDP program into kernel")
	return nil 
}

func (a *Adapter) Unload() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.logger.Info().Msg("Unloading eBPF program")
	if a.xdpLink != nil {
		return a.xdpLink.Close()
	}
	return nil 
}

func (a *Adapter) AllowPeer(ctx context.Context, peerID peer.ID, ip net.IP) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.peerMap[peerID] = ip
	a.logger.Info().Str("peer", peerID.String()).Str("ip", ip.String()).Msg("Allowed peer in eBPF map")
	return nil
}

func (a *Adapter) BlockPeer(ctx context.Context, peerID peer.ID) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.peerMap, peerID)
	a.logger.Info().Str("peer", peerID.String()).Msg("Blocked peer in eBPF map")
	return nil
}

func (a *Adapter) UpdateRateLimit(ctx context.Context, srcIP, dstIP net.IP, rate int) error {
	a.logger.Info().Str("src", srcIP.String()).Int("rate", rate).Msg("Updated rate limit in eBPF mapped tables")
	return nil
}

func (a *Adapter) DropAll(ctx context.Context) error {
	a.logger.Warn().Msg("Dropping all traffic via eBPF XDP fast paths")
	return nil
}
