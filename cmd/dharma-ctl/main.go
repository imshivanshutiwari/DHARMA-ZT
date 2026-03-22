package main

import (
	"context"
	"os"
	"time"

	"github.com/dharma-zt/dharma-zt/pkg/api"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var targetAddr string
var logger zerolog.Logger

func getClient() (api.DharmaServiceClient, *grpc.ClientConn) {
	conn, err := grpc.NewClient(targetAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		logger.Fatal().Err(err).Msg("Did not connect")
	}
	return api.NewDharmaServiceClient(conn), conn
}

var rootCmd = &cobra.Command{
	Use:   "dharma-ctl",
	Short: "Management CLI for DHARMA-ZT nodes",
}

var nodeCmd = &cobra.Command{
	Use:   "node",
	Short: "Manage node state",
}

var bootCmd = &cobra.Command{
	Use:   "boot",
	Short: "Initialize TPM, seal keys, join mesh",
	Run: func(cmd *cobra.Command, args []string) {
		client, conn := getClient()
		defer conn.Close()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		r, err := client.NodeBoot(ctx, &api.Empty{})
		if err != nil {
			logger.Fatal().Err(err).Msg("Could not boot")
		}
		logger.Info().Str("status", r.GetStatus()).Str("message", r.GetMessage()).Msg("Node boot response")
	},
}

var lockdownCmd = &cobra.Command{
	Use:   "lockdown",
	Short: "Trigger immediate key wipe and packet drop",
	Run: func(cmd *cobra.Command, args []string) {
		client, conn := getClient()
		defer conn.Close()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		r, err := client.NodeLockdown(ctx, &api.Empty{})
		if err != nil {
			logger.Fatal().Err(err).Msg("Could not lockdown")
		}
		logger.Info().Str("status", r.GetStatus()).Str("message", r.GetMessage()).Msg("Node lockdown response")
	},
}

var emconCmd = &cobra.Command{
	Use:   "emcon [on|off]",
	Short: "Toggle Emission Control mode",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		client, conn := getClient()
		defer conn.Close()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		active := args[0] == "on"
		r, err := client.SetEMCON(ctx, &api.EMCONRequest{Active: active})
		if err != nil {
			logger.Fatal().Err(err).Msg("Could not set EMCON")
		}
		logger.Info().Str("status", r.GetStatus()).Str("message", r.GetMessage()).Msg("EMCON set response")
	},
}

func main() {
	logger = zerolog.New(os.Stdout).With().Timestamp().Logger()

	rootCmd.PersistentFlags().StringVarP(&targetAddr, "target", "t", "localhost:50051", "gRPC target address")

	nodeCmd.AddCommand(bootCmd, lockdownCmd)
	rootCmd.AddCommand(nodeCmd, emconCmd)

	if err := rootCmd.Execute(); err != nil {
		logger.Fatal().Err(err).Msg("Command execution failed")
	}
}
