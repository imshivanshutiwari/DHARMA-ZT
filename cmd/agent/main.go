package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/dharma-zt/dharma-zt/pkg/api"
	"github.com/dharma-zt/dharma-zt/pkg/core"
	"github.com/dharma-zt/dharma-zt/pkg/ebpf"
	"github.com/dharma-zt/dharma-zt/pkg/identity"
	"github.com/dharma-zt/dharma-zt/pkg/mesh"
	"github.com/dharma-zt/dharma-zt/pkg/policy"
	"github.com/dharma-zt/dharma-zt/pkg/tunnel"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
)

type dharmaServer struct {
	api.UnimplementedDharmaServiceServer
	meshAdapter     *mesh.Libp2pAdapter
	identityAdapter *identity.TPMAdapter
	tunnelAdapter   *tunnel.WireGuardAdapter
	ebpfAdapter     *ebpf.Adapter
	policyAdapter   *policy.OPAAdapter
	logger          zerolog.Logger
}

func (s *dharmaServer) NodeBoot(ctx context.Context, in *api.Empty) (*api.StatusResponse, error) {
	s.logger.Info().Msg("Received Boot command via gRPC")
	if err := s.identityAdapter.Boot(ctx); err != nil {
		return nil, err
	}
	return &api.StatusResponse{Status: "ok", Message: "Node booted"}, nil
}

func (s *dharmaServer) NodeLockdown(ctx context.Context, in *api.Empty) (*api.StatusResponse, error) {
	s.logger.Warn().Msg("Received Lockdown command via gRPC")
	if err := s.identityAdapter.Zeroize(ctx); err != nil {
		s.logger.Error().Err(err).Msg("Failed to zeroize identity adapter")
	}
	if err := s.ebpfAdapter.DropAll(ctx); err != nil {
		s.logger.Error().Err(err).Msg("Failed to drop all eBPF packets")
	}
	return &api.StatusResponse{Status: "lockdown", Message: "Keys zeroized, all packets dropped"}, nil
}

func (s *dharmaServer) SetEMCON(ctx context.Context, in *api.EMCONRequest) (*api.StatusResponse, error) {
	s.logger.Info().Bool("active", in.Active).Msg("Received SetEMCON command via gRPC")
	s.meshAdapter.SetEMCON(in.Active)
	return &api.StatusResponse{Status: "ok", Message: fmt.Sprintf("EMCON set to %v", in.Active)}, nil
}

func main() {
	meshPort := flag.Int("mesh-port", 4001, "Port for Libp2p mesh")
	grpcPort := flag.Int("grpc-port", 50051, "Port for gRPC management API")
	tpmPath := flag.String("tpm-path", "/dev/tpmrm0", "Path to TPM device")
	wgIface := flag.String("wg-iface", "dharma0", "WireGuard interface name")
	ebpfIface := flag.String("ebpf-iface", "eth0", "Network interface for eBPF hooks")
	flag.Parse()

	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	logger := zerolog.New(os.Stdout).With().Timestamp().Logger()

	logger.Info().Msg("Starting DHARMA-ZT Agent")

	eventBus := core.NewEventBus()

	// Initialize Adapters
	tpmAdapter := identity.NewTPMAdapter(*tpmPath, []int{0, 1, 4, 7}, eventBus, nil, logger)

	// Create a dummy privkey for mesh testing since we don't have a real TPM to generate it
	privKey, _, err := crypto.GenerateKeyPair(crypto.Ed25519, 256)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to generate private key")
	}

	meshAdapter, err := mesh.NewLibp2pAdapter(*meshPort, privKey, eventBus, logger)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to init mesh")
	}

	opaAdapter := policy.NewOPAAdapter(eventBus, logger)
	tunnelAdapter := tunnel.NewWireGuardAdapter(*wgIface, eventBus, logger)
	ebpfAdapter := ebpf.NewEBPFAdapter(*ebpfIface, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Subscribe to events
	eventBus.Subscribe(core.EventLockdown, func(c context.Context, e core.Event) {
		logger.Error().Str("reason", fmt.Sprint(e.Payload)).Msg("LOCKDOWN EVENT TRIGGERED! Self-destructing.")
		if err := tpmAdapter.Zeroize(c); err != nil {
			logger.Error().Err(err).Msg("Failed to zeroize during lockdown")
		}
		if err := ebpfAdapter.DropAll(c); err != nil {
			logger.Error().Err(err).Msg("Failed to drop eBPF packets during lockdown")
		}
		os.Exit(1)
	})

	// Start components
	if err := opaAdapter.Start(ctx); err != nil {
		logger.Fatal().Err(err).Msg("Failed to start OPA")
	}
	if err := meshAdapter.Start(ctx); err != nil {
		logger.Fatal().Err(err).Msg("Failed to start Mesh")
	}

	// Setup gRPC Server
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *grpcPort))
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to listen for gRPC")
	}
	grpcServer := grpc.NewServer()
	api.RegisterDharmaServiceServer(grpcServer, &dharmaServer{
		meshAdapter:     meshAdapter,
		identityAdapter: tpmAdapter,
		tunnelAdapter:   tunnelAdapter,
		ebpfAdapter:     ebpfAdapter,
		policyAdapter:   opaAdapter,
		logger:          logger,
	})

	grpcErrChan := make(chan error, 1)
	go func() {
		logger.Info().Int("port", *grpcPort).Msg("gRPC server listening")
		if err := grpcServer.Serve(lis); err != nil {
			grpcErrChan <- fmt.Errorf("gRPC serve failed: %w", err)
		}
	}()

	// Wait for interrupt or error
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	select {
	case <-c:
		logger.Info().Msg("Received interrupt signal")
	case err := <-grpcErrChan:
		logger.Error().Err(err).Msg("gRPC server error")
	}

	logger.Info().Msg("Shutting down DHARMA-ZT Agent")
	grpcServer.GracefulStop()
	meshAdapter.Stop()
	opaAdapter.Stop()
	tunnelAdapter.Stop()
}
