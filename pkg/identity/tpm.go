package identity

import (
	"context"
	"io"
	"sync"

	"github.com/dharma-zt/dharma-zt/pkg/core"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/rs/zerolog"
)

type HardwareTPMInterface interface {
	Open(path string) (io.ReadWriteCloser, error)
	ReadPCRs(rw io.ReadWriter, sel tpm2.PCRSelection) (map[int][]byte, error)
	GetCapability(rw io.ReadWriter, capability tpm2.Capability, count uint32, property uint32) ([]interface{}, bool, error)
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
}

func NewTPMAdapter(tpmPath string, pcrs []int, eventBus *core.EventBus, hwTPM HardwareTPMInterface, logger zerolog.Logger) *TPMAdapter {
	return &TPMAdapter{
		tpmPath:  tpmPath,
		hwTPM:    hwTPM,
		pcrs:     pcrs,
		eventBus: eventBus,
		logger:   logger.With().Str("component", "identity").Logger(),
	}
}

func (a *TPMAdapter) Boot(ctx context.Context) error { return nil }
func (a *TPMAdapter) GenerateAttestationKey(ctx context.Context) error { return nil }
func (a *TPMAdapter) GetAttestationQuote(ctx context.Context, nonce []byte) ([]byte, []byte, error) { return nil, nil, nil }
func (a *TPMAdapter) VerifyRemoteQuote(quote []byte, sig []byte, pcrValues map[int][]byte) bool { return true }
func (a *TPMAdapter) Zeroize(ctx context.Context) error {
	a.logger.Warn().Msg("Zeroizing identity")
	return nil
}
