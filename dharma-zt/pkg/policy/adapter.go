package policy

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/dharma-zt/dharma-zt/pkg/core"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/open-policy-agent/opa/rego"
	"github.com/rs/zerolog"
)

type OPAAdapter struct {
	mu           sync.RWMutex
	logger       zerolog.Logger
	eventBus     *core.EventBus
	policyEngine rego.PreparedEvalQuery
	trustScores  map[peer.ID]float64
}

func NewOPAAdapter(eventBus *core.EventBus, logger zerolog.Logger) *OPAAdapter {
	return &OPAAdapter{
		logger:      logger.With().Str("component", "opa").Logger(),
		eventBus:    eventBus,
		trustScores: make(map[peer.ID]float64),
	}
}

func (a *OPAAdapter) Start(ctx context.Context) error {
	a.logger.Info().Msg("Starting OPA policy engine")

	// Default deny policy
	defaultPolicy := `
package dharma.mesh

default allow = false
`
	if err := a.LoadPolicy(ctx, []byte(defaultPolicy)); err != nil {
		return fmt.Errorf("loading default policy: %w", err)
	}

	return nil
}

func (a *OPAAdapter) Stop() error {
	a.logger.Info().Msg("Stopping OPA policy engine")
	return nil
}

func (a *OPAAdapter) Evaluate(ctx context.Context, req core.PolicyRequest) (core.PolicyDecision, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	input := map[string]interface{}{
		"src_peer_id": req.SrcPeerID.String(),
		"dst_peer_id": req.DstPeerID.String(),
		"src_ip":      req.SrcIP,
		"dst_ip":      req.DstIP,
		"protocol":    req.Protocol,
		"port":        req.Port,
		"trust_score": a.trustScores[req.SrcPeerID],
	}

	results, err := a.policyEngine.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return core.PolicyDecision{Allowed: false, Reason: "eval error"}, fmt.Errorf("policy evaluation failed: %w", err)
	}

	if len(results) == 0 || len(results[0].Expressions) == 0 {
		return core.PolicyDecision{Allowed: false, Reason: "no result"}, nil
	}

	allowed, ok := results[0].Expressions[0].Value.(bool)
	if !ok {
		return core.PolicyDecision{Allowed: false, Reason: "invalid result type"}, nil
	}

	return core.PolicyDecision{
		Allowed: allowed,
		Reason:  "policy match",
	}, nil
}

func (a *OPAAdapter) LoadPolicy(ctx context.Context, policyData []byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	query, err := rego.New(
		rego.Query("data.dharma.mesh.allow"),
		rego.Module("dharma.rego", string(policyData)),
	).PrepareForEval(ctx)
	if err != nil {
		return fmt.Errorf("preparing rego query: %w", err)
	}

	a.policyEngine = query
	a.logger.Info().Msg("Loaded new policy successfully")

	a.eventBus.Publish(ctx, core.Event{
		ID:        "policy-update-" + time.Now().String(),
		Type:      core.EventPolicyUpdated,
		Timestamp: time.Now(),
		Payload:   string(policyData),
	})

	return nil
}

func (a *OPAAdapter) CalculateTrustScore(ctx context.Context, peerID peer.ID, metrics map[string]float64) (float64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	hwAuth := metrics["hardware_auth"]  // e.g., 1.0 if TPM attestation valid
	behav := metrics["behavioral"]      // e.g., normal traffic patterns
	policyComp := metrics["compliance"] // e.g., adhering to rules
	netHealth := metrics["health"]      // e.g., low latency

	// Formula: T = 0.40*HW + 0.25*Behav + 0.20*Policy + 0.15*Health
	score := (0.40 * hwAuth) + (0.25 * behav) + (0.20 * policyComp) + (0.15 * netHealth)

	// Clamp between 0.0 and 1.0
	if score > 1.0 {
		score = 1.0
	} else if score < 0.0 {
		score = 0.0
	}

	a.trustScores[peerID] = score
	a.logger.Debug().Str("peer", peerID.String()).Float64("score", score).Msg("Calculated trust score")

	return score, nil
}
