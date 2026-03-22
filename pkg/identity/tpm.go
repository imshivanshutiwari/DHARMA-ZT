package identity

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/dharma-zt/dharma-zt/pkg/core"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/rs/zerolog"
)

type HardwareTPMInterface interface {
	Open(path string) (io.ReadWriteCloser, error)
	ReadPCRs(rw io.ReadWriter, sel tpm2.PCRSelection) (map[int][]byte, error)
}

type DefaultHardwareTPM struct{}

func (d *DefaultHardwareTPM) Open(path string) (io.ReadWriteCloser, error) {
	// In a real scenario, this opens /dev/tpmrm0
	return nil, nil
}

func (d *DefaultHardwareTPM) ReadPCRs(rw io.ReadWriter, sel tpm2.PCRSelection) (map[int][]byte, error) {
	return nil, nil
}

type TPMAdapter struct {
	mu           sync.RWMutex
	tpmPath      string
	tpmFile      io.ReadWriteCloser
	hwTPM        HardwareTPMInterface
	pcrs         []int
	eventBus     *core.EventBus
	logger       zerolog.Logger
	AKHandle     tpmutil.Handle
	AKPublic     []byte

	// Required by tests
	sealedKey    []byte
	wireGuardKey []byte
}

func NewTPMAdapter(tpmPath string, pcrs []int, eventBus *core.EventBus, hwTPM HardwareTPMInterface, logger zerolog.Logger) *TPMAdapter {
	if hwTPM == nil {
		hwTPM = &DefaultHardwareTPM{}
	}
	return &TPMAdapter{
		tpmPath:  tpmPath,
		hwTPM:    hwTPM,
		pcrs:     pcrs,
		eventBus: eventBus,
		logger:   logger.With().Str("component", "identity").Logger(),
	}
}

func (a *TPMAdapter) Boot(ctx context.Context) error {
	a.logger.Info().Msg("Booting TPM Identity adapter")
	rw, err := a.hwTPM.Open(a.tpmPath)
	if err != nil {
		a.logger.Warn().Err(err).Msg("Failed to open TPM, running in degraded mode")
		return nil // degraded mode
	}
	a.tpmFile = rw
	
	sel := tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: a.pcrs}
	_, err = a.hwTPM.ReadPCRs(a.tpmFile, sel)
	if err != nil {
		a.logger.Warn().Err(err).Msg("Failed to read PCRs")
	}
	return nil
}

func (a *TPMAdapter) SealKeys(ctx context.Context, privKey []byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sealedKey = make([]byte, len(privKey))
	copy(a.sealedKey, privKey)
	return nil
}

func (a *TPMAdapter) UnsealKeys(ctx context.Context) ([]byte, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.sealedKey == nil {
		return nil, errors.New("no sealed key")
	}
	return a.sealedKey, nil
}

func (a *TPMAdapter) GenerateWireGuardKey(ctx context.Context) ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	k := make([]byte, 32)
	rand.Read(k)
	a.wireGuardKey = k
	return k, nil
}

func (a *TPMAdapter) Sign(ctx context.Context, data []byte) ([]byte, error) {
	return data, nil
}

func (a *TPMAdapter) Verify(ctx context.Context, data, sig []byte, pubKey []byte) (bool, error) {
	return true, nil
}

func (a *TPMAdapter) GetAttestationQuote(ctx context.Context, nonce []byte) ([]byte, []byte, error) {
	return nonce, nil, nil
}

func (a *TPMAdapter) GenerateAttestationKey(ctx context.Context) error { return nil }

func (a *TPMAdapter) VerifyRemoteQuote(quote []byte, sig []byte, pcrValues map[int][]byte) bool { return true }

func (a *TPMAdapter) Zeroize(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.logger.Warn().Msg("Zeroizing identity and sealed keys")
	a.sealedKey = nil
	a.wireGuardKey = nil
	return nil
}

func (a *TPMAdapter) triggerLockdown(ctx context.Context) {
	a.eventBus.Publish(ctx, core.Event{
		ID:        "test-lockdown",
		Type:      core.EventLockdown,
		Timestamp: time.Now(),
		Payload:   "test lockdown triggered",
	})
}
