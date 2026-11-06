package cmd

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/util"
)

var profileListShowID bool

var profileCmd = &cobra.Command{
	Use:   "profile",
	Short: "Manage NetBird client profiles",
	Long:  `Commands to list, add, remove, and switch profiles. Profiles allow you to maintain different accounts in one client app.`,
}

var profileListCmd = &cobra.Command{
	Use:     "list",
	Short:   "List all profiles",
	Long:    `List all available profiles in the NetBird client.`,
	Aliases: []string{"ls"},
	RunE:    listProfilesFunc,
}

var profileAddCmd = &cobra.Command{
	Use:   "add <profile_name>",
	Short: "Add a new profile",
	Long:  `Add a new profile. Profile name is free-form, a unique ID is generated for the on-disk config file.`,
	Args:  cobra.ExactArgs(1),
	RunE:  addProfileFunc,
}

var profileRenameCmd = &cobra.Command{
	Use:   "rename <profile> <new_profile_name>",
	Short: "Renames an existing profile",
	Long:  `Renames an existing profile (by a name, ID, or unique ID prefix). Profile name is free-form.`,
	Args:  cobra.ExactArgs(2),
	RunE:  renameProfileFunc,
}

var profileRemoveCmd = &cobra.Command{
	Use:     "remove <profile>",
	Short:   "Remove a profile",
	Long:    `Remove a profile by name, ID, or unique ID prefix.`,
	Aliases: []string{"rm"},
	Args:    cobra.ExactArgs(1),
	RunE:    removeProfileFunc,
}

var profileSelectCmd = &cobra.Command{
	Use:   "select <profile>",
	Short: "Select a profile",
	Long: `Make the specified profile active. Accepts a name, ID, or unique ID prefix.
With concurrent profiles enabled on the daemon, selecting only moves the focus and leaves every connection as it is.`,
	Args: cobra.ExactArgs(1),
	RunE: selectProfileFunc,
}

func init() {
	profileListCmd.Flags().BoolVar(&profileListShowID, "show-id", false, "show the profile ID column")
}

func setupCmd(cmd *cobra.Command) error {
	SetFlagsFromEnvVars(rootCmd)
	SetFlagsFromEnvVars(cmd)

	cmd.SetOut(cmd.OutOrStdout())

	err := util.InitLog(logLevel, "console")
	if err != nil {
		return err
	}

	return nil
}

func listProfilesFunc(cmd *cobra.Command, _ []string) error {
	if err := setupCmd(cmd); err != nil {
		return err
	}

	conn, err := DialClientGRPCServer(cmd.Context(), daemonAddr)
	if err != nil {
		return fmt.Errorf("connect to service CLI interface: %w", err)
	}
	defer conn.Close()

	currUser, err := profilemanager.InvokingUser()
	if err != nil {
		return fmt.Errorf("get current user: %w", err)
	}

	daemonClient := proto.NewDaemonServiceClient(conn)

	resp, err := daemonClient.ListProfiles(cmd.Context(), &proto.ListProfilesRequest{
		Username: currUser.Username,
	})
	if err != nil {
		return err
	}

	connection, withStatus, err := profileConnectionStatus(cmd.Context(), daemonClient)
	if err != nil {
		return err
	}

	tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	printProfileHeader(tw, withStatus)
	for _, profile := range resp.Profiles {
		marker := ""
		if profile.IsActive {
			marker = "✓"
		}
		name := profilemanager.StripCtrlChars(profile.Name)
		id := profilemanager.ID(profile.Id)
		row := []string{name, marker}
		if profileListShowID {
			row = []string{id.ShortID(), name, marker}
		}
		if withStatus {
			row = append(row, connection.of(profile))
		}
		fmt.Fprintln(tw, strings.Join(row, "\t"))
	}
	return tw.Flush()
}

func printProfileHeader(tw *tabwriter.Writer, withStatus bool) {
	header := []string{"NAME", "ACTIVE"}
	if profileListShowID {
		header = []string{"ID", "NAME", "ACTIVE"}
	}
	if withStatus {
		header = append(header, "STATUS")
	}
	fmt.Fprintln(tw, strings.Join(header, "\t"))
}

// connectionStatuses is the connection status of the profiles of a daemon with concurrent
// profiles, from its sessions. A profile without a session is not connected.
type connectionStatuses map[string]string

// profileConnectionStatus reads the connection status of the profiles. It reports false for a
// daemon without concurrent profiles, whose list stays what it was.
func profileConnectionStatus(ctx context.Context, client proto.DaemonServiceClient) (connectionStatuses, bool, error) {
	state, err := daemonConcurrentProfiles(ctx, client)
	if err != nil {
		return nil, false, err
	}
	if state != gateEnabled {
		return nil, false, nil
	}

	resp, err := client.Status(ctx, &proto.StatusRequest{})
	if err != nil {
		return nil, false, fmt.Errorf("get service status: %w", err)
	}
	statuses := make(connectionStatuses, len(resp.GetSessions()))
	for _, s := range resp.GetSessions() {
		statuses[s.GetProfileId()] = s.GetStatus()
	}
	return statuses, true, nil
}

// of is the status shown for profile. The daemon's own answer wins over what the sessions say.
func (c connectionStatuses) of(profile *proto.Profile) string {
	if status := profile.GetConnectionStatus(); status != "" {
		return status
	}
	if status, ok := c[profile.GetId()]; ok {
		return status
	}
	return "Idle"
}

func addProfileFunc(cmd *cobra.Command, args []string) error {
	if err := setupCmd(cmd); err != nil {
		return err
	}

	currUser, err := profilemanager.InvokingUser()
	if err != nil {
		return fmt.Errorf("get current user: %w", err)
	}

	conn, err := DialClientGRPCServer(cmd.Context(), daemonAddr)
	if err != nil {
		return fmt.Errorf("connect to service CLI interface: %w", err)
	}
	defer conn.Close()

	daemonClient := proto.NewDaemonServiceClient(conn)
	profileName := args[0]

	id, err := addProfileOnDaemon(cmd.Context(), daemonClient, profileName, currUser.Username)
	if err != nil {
		return err
	}

	dupCount, _ := countProfilesWithName(cmd.Context(), daemonClient, currUser.Username, profileName)
	if dupCount > 1 {
		cmd.Printf("Warning: %d other profile(s) already use the name %q.\n", dupCount-1, profileName)
		cmd.Println("Use `netbird profile list --show-id` to disambiguate later.")
	}

	cmd.Printf("Profile added: %s  %s\n", id.ShortID(), profilemanager.StripCtrlChars(profileName))
	return nil

}

func renameProfileFunc(cmd *cobra.Command, args []string) error {
	if err := setupCmd(cmd); err != nil {
		return err
	}

	conn, err := DialClientGRPCServer(cmd.Context(), daemonAddr)
	if err != nil {
		return fmt.Errorf("connect to service CLI interface: %w", err)
	}
	defer conn.Close()

	currUser, err := profilemanager.InvokingUser()
	if err != nil {
		return fmt.Errorf("get current user: %w", err)
	}

	daemonClient := proto.NewDaemonServiceClient(conn)
	handle := args[0]
	newProfilename := args[1]

	resp, err := daemonClient.RenameProfile(cmd.Context(), &proto.RenameProfileRequest{
		Handle:         handle,
		Username:       currUser.Username,
		NewProfileName: newProfilename,
	})
	if err != nil {
		return wrapAmbiguityError(err, handle)
	}

	dupCount, _ := countProfilesWithName(cmd.Context(), daemonClient, currUser.Username, newProfilename)
	if dupCount > 1 {
		cmd.Printf("Warning: %d other profile(s) already use the name %q.\n", dupCount-1, newProfilename)
		cmd.Println("Use `netbird profile list --show-id` to disambiguate later.")
	}

	cmd.Printf("Profile renamed from %s to %s\n", profilemanager.StripCtrlChars(resp.OldProfileName), profilemanager.StripCtrlChars(newProfilename))

	return nil
}

func countProfilesWithName(ctx context.Context, c proto.DaemonServiceClient, username, name string) (int, error) {
	resp, err := c.ListProfiles(ctx, &proto.ListProfilesRequest{Username: username})
	if err != nil {
		return 0, err
	}
	n := 0
	for _, p := range resp.Profiles {
		if p.Name == name {
			n++
		}
	}
	return n, nil
}

func removeProfileFunc(cmd *cobra.Command, args []string) error {
	if err := setupCmd(cmd); err != nil {
		return err
	}

	conn, err := DialClientGRPCServer(cmd.Context(), daemonAddr)
	if err != nil {
		return fmt.Errorf("connect to service CLI interface: %w", err)
	}
	defer conn.Close()

	currUser, err := profilemanager.InvokingUser()
	if err != nil {
		return fmt.Errorf("get current user: %w", err)
	}

	daemonClient := proto.NewDaemonServiceClient(conn)
	handle := args[0]

	resp, err := daemonClient.RemoveProfile(cmd.Context(), &proto.RemoveProfileRequest{
		ProfileName: handle,
		Username:    currUser.Username,
	})
	if err != nil {
		return explainRunningSession(cmd.Context(), daemonClient, err, wrapAmbiguityError(err, handle), handle)
	}

	cmd.Printf("Profile removed: %s\n", resp.Id)
	return nil
}

func selectProfileFunc(cmd *cobra.Command, args []string) error {
	if err := setupCmd(cmd); err != nil {
		return err
	}

	profileManager := profilemanager.NewProfileManager()
	handle := args[0]

	currUser, err := profilemanager.InvokingUser()
	if err != nil {
		return fmt.Errorf("get current user: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*7)
	defer cancel()
	conn, err := DialClientGRPCServer(ctx, daemonAddr)
	if err != nil {
		return fmt.Errorf("connect to service CLI interface: %w", err)
	}
	defer conn.Close()

	daemonClient := proto.NewDaemonServiceClient(conn)

	switchResp, err := daemonClient.SwitchProfile(ctx, &proto.SwitchProfileRequest{
		ProfileName: &handle,
		Username:    &currUser.Username,
	})
	if err != nil {
		return wrapAmbiguityError(err, handle)
	}

	if err := profileManager.SwitchProfile(profilemanager.ID(switchResp.Id)); err != nil {
		return err
	}

	// With concurrent profiles the selection only moves the focus. The connections stay.
	state, err := daemonConcurrentProfiles(ctx, daemonClient)
	if err != nil {
		return err
	}
	if state != gateEnabled {
		if err := downConnectedProfile(ctx, daemonClient); err != nil {
			return err
		}
	}

	id := profilemanager.ID(switchResp.Id)
	cmd.Printf("Profile switched to: %s\n", id.ShortID())
	return nil
}

// explainRunningSession tells what to do about a profile that cannot be removed or logged out
// while it runs, when the daemon runs concurrent profiles. Otherwise the error is the one of
// today.
func explainRunningSession(ctx context.Context, client proto.DaemonServiceClient, daemonErr, fallback error, handle string) error {
	if gstatus.Code(daemonErr) != codes.FailedPrecondition {
		return fallback
	}
	state, err := daemonConcurrentProfiles(ctx, client)
	if err != nil || state != gateEnabled {
		return fallback
	}
	return runningSessionError(daemonErr, handle)
}

// downConnectedProfile ends the connection of the daemon if there is one, which a daemon with
// a single connection must do for the profile selected to be the one it is connected with.
func downConnectedProfile(ctx context.Context, client proto.DaemonServiceClient) error {
	status, err := client.Status(ctx, &proto.StatusRequest{})
	if err != nil {
		return fmt.Errorf("get service status: %w", err)
	}

	if status.Status == string(internal.StatusConnected) {
		if _, err := client.Down(ctx, &proto.DownRequest{}); err != nil {
			return fmt.Errorf("call service down method: %w", err)
		}
	}
	return nil
}

// wrapAmbiguityError turns the daemon's gRPC InvalidArgument errors
// (which carry the resolver's message verbatim) into CLI-friendly text
// that points the user at --show-id.
func wrapAmbiguityError(err error, handle string) error {
	if err == nil {
		return nil
	}
	st, ok := gstatus.FromError(err)
	if !ok {
		return err
	}
	switch st.Code() {
	case codes.InvalidArgument:
		msg := st.Message()
		if strings.Contains(msg, "ambiguous") {
			return errors.New(msg + "\nRun `netbird profile list --show-id` to see IDs, then select by ID prefix:\n  netbird profile select|remove <id-prefix>")
		}
	case codes.NotFound:
		return fmt.Errorf("profile %q not found", handle)
	}
	return err
}

// addProfileOnDaemon issues the AddProfile RPC on an existing daemon client
// and returns the new profile's ID. It is the single entry point for profile
// creation, shared by `netbird profile add` and the `netbird up --profile
// <name>` auto-create path.
func addProfileOnDaemon(ctx context.Context, client proto.DaemonServiceClient, profileName, username string) (profilemanager.ID, error) {
	resp, err := client.AddProfile(ctx, &proto.AddProfileRequest{
		ProfileName: profileName,
		Username:    username,
	})
	if err != nil {
		return "", fmt.Errorf("add profile failed: %w", err)
	}

	return profilemanager.ID(resp.Id), nil
}
