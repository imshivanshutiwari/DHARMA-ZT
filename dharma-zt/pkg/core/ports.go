package core

import (
	"context"
	"net"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

// MeshPort defines operations for the P2P mesh network.
type MeshPort interface {
	Start(ctx context.Context) error
	Stop() error
	GetPeers() []peer.ID
	GetPeerStatus(id peer.ID) (PeerStatus, error)
	SetEMCON(active bool) error
	BroadcastAlert(ctx context.Context, alertType string, data []byte) error
}

// PeerStatus represents the connection and trust state of a peer.
type PeerStatus struct {
	ID         peer.ID
	Connected  bool
	TrustScore float64
	LastSeen   time.Time
	Roles      []string
}

// PolicyPort defines operations for the OPA policy engine.
type PolicyPort interface {
	Start(ctx context.Context) error
	Stop() error
	Evaluate(ctx context.Context, req PolicyRequest) (PolicyDecision, error)
	LoadPolicy(ctx context.Context, policyData []byte) error
	CalculateTrustScore(ctx context.Context, peerID peer.ID, metrics map[string]float64) (float64, error)
}

// PolicyRequest is the input to the OPA evaluation.
type PolicyRequest struct {
	SrcPeerID peer.ID `json:"src_peer_id"`
	DstPeerID peer.ID `json:"dst_peer_id"`
	SrcIP     string  `json:"src_ip"`
	DstIP     string  `json:"dst_ip"`
	Protocol  string  `json:"protocol"`
	Port      int     `json:"port"`
}

// PolicyDecision is the output from OPA evaluation.
type PolicyDecision struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
}

// IdentityPort defines operations for the hardware root of trust (TPM).
type IdentityPort interface {
	Boot(ctx context.Context) error
	SealKeys(ctx context.Context, privKey []byte) error
	UnsealKeys(ctx context.Context) ([]byte, error)
	Sign(ctx context.Context, data []byte) ([]byte, error)
	Verify(ctx context.Context, data, sig []byte, pubKey []byte) (bool, error)
	GetAttestationQuote(ctx context.Context, nonce []byte) ([]byte, error)
	Zeroize(ctx context.Context) error
	GenerateWireGuardKey(ctx context.Context) ([]byte, error)
}

// TunnelPort defines operations for the WireGuard networking layer.
type TunnelPort interface {
	Start(ctx context.Context, privateKey []byte, port int) error
	Stop() error
	AddPeer(ctx context.Context, pubKey []byte, endpoint string, allowedIPs []net.IPNet) error
	RemovePeer(ctx context.Context, pubKey []byte) error
	RotateKey(ctx context.Context, newPrivateKey []byte) error
}

// KernelPort defines operations for eBPF networking and filtering.
type KernelPort interface {
	Load(ctx context.Context) error
	Unload() error
	AllowPeer(ctx context.Context, peerID peer.ID, ip net.IP) error
	BlockPeer(ctx context.Context, peerID peer.ID) error
	UpdateRateLimit(ctx context.Context, srcIP, dstIP net.IP, rate int) error
	DropAll(ctx context.Context) error
}
