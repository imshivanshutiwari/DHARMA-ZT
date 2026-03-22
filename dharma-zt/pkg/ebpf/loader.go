package ebpf

import (
	"context"
	"net"
	"sync"

	"github.com/cilium/ebpf/link"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/rs/zerolog"
)

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

func (a *Adapter) Load(ctx context.Context) error { return nil }
func (a *Adapter) Unload() error { return nil }
func (a *Adapter) DropAll(ctx context.Context) error {
	a.logger.Warn().Msg("Dropping all traffic")
	return nil
}
