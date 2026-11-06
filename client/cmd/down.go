package cmd

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/netbirdio/netbird/util"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/client/proto"
)

var downCmd = &cobra.Command{
	Use:   "down",
	Short: "Disconnect from the NetBird network",
	Long: "Disconnect the NetBird client from the network and management service. This will terminate all active connections with the remote peers.\n\n" +
		"With concurrent profiles enabled on the daemon, down disconnects the focused session only and names the sessions that keep running. " +
		"Use --profile to disconnect another session and --all to disconnect every session.",
	RunE: func(cmd *cobra.Command, args []string) error {
		SetFlagsFromEnvVars(rootCmd)

		cmd.SetOut(cmd.OutOrStdout())

		err := util.InitLog(logLevel, util.LogConsole)
		if err != nil {
			log.Errorf("failed initializing log %v", err)
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Second*20)
		defer cancel()

		conn, err := DialClientGRPCServer(ctx, daemonAddr)
		if err != nil {
			log.Errorf("failed to connect to service CLI interface %v", err)
			return err
		}
		defer conn.Close()

		daemonClient := proto.NewDaemonServiceClient(conn)

		req, err := downRequestFromFlags(ctx, daemonClient)
		if err != nil {
			return err
		}

		if _, err := daemonClient.Down(ctx, req); err != nil {
			log.Errorf("call service down method: %v", err)
			return withRunningSessions(ctx, daemonClient, req, err)
		}

		cmd.Println("Disconnected")
		cmd.Print(runningSessionsHint(ctx, daemonClient, req))
		return nil
	},
}

func init() {
	downCmd.Flags().StringVar(&sessionProfile, sessionProfileFlag, "", "profile whose session to disconnect (needs a daemon with concurrent profiles)")
	downCmd.Flags().BoolVar(&downAll, downAllFlag, false, downAllDesc)
	downCmd.MarkFlagsMutuallyExclusive(sessionProfileFlag, downAllFlag)
}

// downRequestFromFlags builds the Down request. Without a flag it is the plain request that has
// always meant the one connection, which with concurrent profiles is the focused session.
func downRequestFromFlags(ctx context.Context, client proto.DaemonServiceClient) (*proto.DownRequest, error) {
	if downAll {
		if err := requireConcurrentProfiles(ctx, client, downAllFlag); err != nil {
			return nil, err
		}
		return &proto.DownRequest{All: true}, nil
	}

	selector, err := sessionFromFlag(ctx, client)
	if err != nil {
		return nil, err
	}
	return &proto.DownRequest{Session: selector}, nil
}

// runningSessionsHint names the sessions that run on after a Down of the focused one, so that a
// user who typed a plain `netbird down` sees that it did not end them. It is empty when the Down
// named its target, when the daemon runs without concurrent profiles or when nothing else runs.
func runningSessionsHint(ctx context.Context, client proto.DaemonServiceClient, req *proto.DownRequest) string {
	if req.GetAll() || req.GetSession() != nil {
		return ""
	}
	state, err := daemonConcurrentProfiles(ctx, client)
	if err != nil || state != gateEnabled {
		return ""
	}
	resp, err := client.Status(ctx, &proto.StatusRequest{})
	if err != nil {
		log.Debugf("list the sessions that keep running: %v", err)
		return ""
	}
	return stillRunningHint(resp.GetSessions())
}

// withRunningSessions adds the sessions that run to the error of a plain Down, which fails when
// the focused session is not up although others are.
func withRunningSessions(ctx context.Context, client proto.DaemonServiceClient, req *proto.DownRequest, err error) error {
	hint := strings.TrimSpace(runningSessionsHint(ctx, client, req))
	if hint == "" {
		return err
	}
	return fmt.Errorf("%w\n%s", err, hint)
}
