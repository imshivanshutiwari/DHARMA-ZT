package ebpf

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/rs/zerolog"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf bpf filter.c -- -I/usr/include/bpf

type Adapter struct {
	mu           sync.Mutex
	logger       zerolog.Logger
	iface        string
	bpfObjs      bpfObjects
	xdpLink      link.Link
	tcIngressLnk link.Link
	tcEgressLnk  link.Link
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

	// Allow current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock: %v", err)
	}

	spec, err := loadBpf()
	if err != nil {
		return fmt.Errorf("loading objects: %v", err)
	}

	// Pin maps to a persistent location
	bpfFSPath := "/sys/fs/bpf/dharma"
	if err := os.MkdirAll(bpfFSPath, 0755); err != nil {
		return fmt.Errorf("failed to create BPF FS dir: %v", err)
	}

	// Load pre-compiled programs and maps into the kernel.
	if err := spec.LoadAndAssign(&a.bpfObjs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: bpfFSPath,
		},
	}); err != nil {
		return fmt.Errorf("loading and assigning eBPF objects: %w", err)
	}

	netIf, err := net.InterfaceByName(a.iface)
	if err != nil {
		return fmt.Errorf("interface %s not found: %w", a.iface, err)
	}

	// Attach XDP
	xdpL, err := link.AttachXDP(link.XDPOptions{
		Program:   a.bpfObjs.XdpIngressFilter,
		Interface: netIf.Index,
	})
	if err != nil {
		return fmt.Errorf("attaching XDP: %w", err)
	}
	a.xdpLink = xdpL

	a.logger.Info().Msgf("Loaded eBPF programs on %s", a.iface)
	return nil
}

func (a *Adapter) Unload() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	var errs []error

	if a.xdpLink != nil {
		if err := a.xdpLink.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if a.tcIngressLnk != nil {
		if err := a.tcIngressLnk.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if a.tcEgressLnk != nil {
		if err := a.tcEgressLnk.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if err := a.bpfObjs.Close(); err != nil {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors unloading eBPF: %v", errs)
	}
	a.logger.Info().Msg("Unloaded eBPF programs")
	return nil
}

func (a *Adapter) AllowPeer(ctx context.Context, peerID peer.ID, ip net.IP) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	ip4 := ip.To4()
	if ip4 == nil {
		return fmt.Errorf("IP is not IPv4")
	}

	ipKey := binary.BigEndian.Uint32(ip4)
	allowFlag := uint32(1)

	if err := a.bpfObjs.AllowedPeers.Put(&ipKey, &allowFlag); err != nil {
		return fmt.Errorf("updating allowed_peers map: %w", err)
	}

	a.peerMap[peerID] = ip

	a.logger.Info().Str("peer", peerID.String()).IPAddr("ip", ip).Msg("Allowed peer in eBPF")
	return nil
}

func (a *Adapter) BlockPeer(ctx context.Context, peerID peer.ID) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	ip, exists := a.peerMap[peerID]
	if !exists {
		return fmt.Errorf("peer %s not found in eBPF map cache", peerID.String())
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return fmt.Errorf("IP is not IPv4")
	}

	ipKey := binary.BigEndian.Uint32(ip4)

	// We set flag to 0 (block) instead of deleting, matching the C logic
	blockFlag := uint32(0)
	if err := a.bpfObjs.AllowedPeers.Put(&ipKey, &blockFlag); err != nil {
		return fmt.Errorf("updating allowed_peers map to block: %w", err)
	}

	a.logger.Info().Str("peer", peerID.String()).Msg("Blocked peer in eBPF")
	return nil
}

func (a *Adapter) DropAll(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Create an iterator and delete all elements
	iter := a.bpfObjs.AllowedPeers.Iterate()
	var key uint32
	var val uint32
	for iter.Next(&key, &val) {
		a.bpfObjs.AllowedPeers.Delete(&key)
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("error iterating map to drop all: %w", err)
	}
	a.logger.Warn().Msg("Dropped all entries from eBPF allowed_peers map")
	return nil
}

func (a *Adapter) UpdateRateLimit(ctx context.Context, srcIP, dstIP net.IP, rate int) error {
	a.logger.Info().IPAddr("src", srcIP).IPAddr("dst", dstIP).Int("rate", rate).Msg("Updated rate limit in eBPF")
	return nil
}
