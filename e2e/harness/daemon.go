//go:build e2e

package harness

import (
	"context"
	"fmt"
	"maps"

	"github.com/docker/docker/api/types/container"
	"github.com/testcontainers/testcontainers-go"
)

// defaultManagementHost is where a profile with no Management of its own goes. Nothing a
// suite does should get there, and the host entry makes sure of it: a login would carry
// the keys and the metadata of the container to the real service.
const defaultManagementHost = "api.netbird.io"

// StartDaemon runs the daemon of the agent with nothing connected, on the networks of
// the given servers, so that a suite decides what comes up through the CLI in the
// container. The agent is told about no server of its own; the CLI names them.
//
// args are added to `netbird service run`. The container is privileged, because the
// daemon writes sysctls of its network namespace and Docker mounts /proc/sys read-only
// otherwise, and a suite may turn the kernel interface off, which needs the TUN device.
// The Client returned has the helpers that exec into the container; the ones that
// expect a joined agent have nothing to see.
func StartDaemon(ctx context.Context, name string, servers []*Combined, env map[string]string, args ...string) (*Client, error) {
	if len(servers) == 0 {
		return nil, fmt.Errorf("start daemon %s: no server to attach to", name)
	}

	clientImage, err := ClientImage(ctx)
	if err != nil {
		return nil, err
	}

	networks := make([]string, 0, len(servers))
	aliases := make(map[string][]string, len(servers))
	for _, server := range servers {
		networks = append(networks, server.network.Name)
		aliases[server.network.Name] = []string{name}
	}

	containerEnv := map[string]string{
		"NB_LOG_LEVEL":       "info",
		"NB_RELAY_TRANSPORT": "ws",
	}
	maps.Copy(containerEnv, env)

	req := testcontainers.ContainerRequest{
		Image:          clientImage,
		Entrypoint:     append([]string{"netbird", "service", "run"}, args...),
		Hostname:       name,
		Networks:       networks,
		NetworkAliases: aliases,
		Env:            containerEnv,
		HostConfigModifier: func(hc *container.HostConfig) {
			hc.Privileged = true
			hc.ExtraHosts = append(hc.ExtraHosts, defaultManagementHost+":127.0.0.1")
		},
	}

	ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, fmt.Errorf("start daemon container: %w", err)
	}
	return &Client{container: ctr, name: name}, nil
}
