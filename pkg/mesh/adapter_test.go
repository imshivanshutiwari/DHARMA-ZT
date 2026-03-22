package mesh

import (
	"context"
	"testing"

	"github.com/dharma-zt/dharma-zt/pkg/core"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
)

func TestLibp2pAdapter_EMCON(t *testing.T) {
	logger := zerolog.Nop()
	eventBus := core.NewEventBus()

	privKey, _, err := crypto.GenerateKeyPair(crypto.Ed25519, 256)
	assert.NoError(t, err)

	adapter, err := NewLibp2pAdapter(0, privKey, eventBus, logger)
	assert.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = adapter.Start(ctx)
	assert.NoError(t, err)

	// Test enabling EMCON
	err = adapter.SetEMCON(true)
	assert.NoError(t, err)
	assert.True(t, adapter.emconActive)

	// Test disabling EMCON
	err = adapter.SetEMCON(false)
	assert.NoError(t, err)
	assert.False(t, adapter.emconActive)

	// Cleanup
	err = adapter.Stop()
	assert.NoError(t, err)
}
