package identity

import (
	"context"
	"io"
	"os"
	"testing"
	"time"

	"github.com/dharma-zt/dharma-zt/pkg/core"
	"github.com/google/go-tpm/tpm2"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockTPMInterface struct {
	mock.Mock
}

func (m *MockTPMInterface) Open(path string) (io.ReadWriteCloser, error) {
	args := m.Called(path)
	if args.Get(0) != nil {
		return args.Get(0).(io.ReadWriteCloser), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockTPMInterface) ReadPCRs(rw io.ReadWriter, sel tpm2.PCRSelection) (map[int][]byte, error) {
	args := m.Called(rw, sel)
	return args.Get(0).(map[int][]byte), args.Error(1)
}

type dummyRWC struct{}

func (d *dummyRWC) Read(p []byte) (n int, err error)  { return 0, nil }
func (d *dummyRWC) Write(p []byte) (n int, err error) { return 0, nil }
func (d *dummyRWC) Close() error                      { return nil }

func TestTPMAdapter_SealUnseal(t *testing.T) {
	logger := zerolog.New(os.Stdout)
	eventBus := core.NewEventBus()
	mockHwTPM := new(MockTPMInterface)

	mockHwTPM.On("Open", "/dev/null").Return(&dummyRWC{}, nil)
	mockHwTPM.On("ReadPCRs", mock.Anything, mock.Anything).Return(map[int][]byte{0: []byte("pcr0"), 1: []byte("pcr1")}, nil)

	adapter := NewTPMAdapter("/dev/null", []int{0, 1}, eventBus, mockHwTPM, logger)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := adapter.Boot(ctx)
	assert.NoError(t, err)

	privKey := []byte("super-secret-key")

	err = adapter.SealKeys(ctx, privKey)
	assert.NoError(t, err)

	unsealed, err := adapter.UnsealKeys(ctx)
	assert.NoError(t, err)
	assert.Equal(t, privKey, unsealed)

	adapter.Zeroize(ctx)
	unsealed, err = adapter.UnsealKeys(ctx)
	assert.Error(t, err)
	assert.Nil(t, unsealed)
}

func TestTPMAdapter_Zeroize(t *testing.T) {
	logger := zerolog.New(os.Stdout)
	eventBus := core.NewEventBus()
	mockHwTPM := new(MockTPMInterface)

	adapter := NewTPMAdapter("/dev/null", []int{0}, eventBus, mockHwTPM, logger)
	adapter.sealedKey = []byte("secret")
	adapter.wireGuardKey = []byte("wg-secret")

	adapter.Zeroize(context.Background())

	assert.Nil(t, adapter.sealedKey)
	assert.Nil(t, adapter.wireGuardKey)
}

func TestTPMAdapter_LockdownEvent(t *testing.T) {
	logger := zerolog.New(os.Stdout)
	eventBus := core.NewEventBus()
	mockHwTPM := new(MockTPMInterface)

	adapter := NewTPMAdapter("/dev/null", []int{0}, eventBus, mockHwTPM, logger)

	eventReceived := make(chan bool)
	eventBus.Subscribe(core.EventLockdown, func(ctx context.Context, e core.Event) {
		eventReceived <- true
	})

	adapter.triggerLockdown(context.Background())

	select {
	case <-eventReceived:
		// Success
	case <-time.After(1 * time.Second):
		t.Fatal("Lockdown event not received")
	}
}
