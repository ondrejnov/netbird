package hostcoord

import (
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// perDeviceKernel is a route table where every device has routes of its own, as on Windows: an
// install adds a route next to the one another device has, and only a remove takes it away.
type perDeviceKernel struct {
	mu      sync.Mutex
	routes  map[string]bool
	ops     []string
	failDel map[string]error
}

func newPerDeviceKernel() *perDeviceKernel {
	return &perDeviceKernel{routes: map[string]bool{}, failDel: map[string]error{}}
}

func (k *perDeviceKernel) claim(dev string) RouteClaim {
	return RouteClaim{
		Dev:              dev,
		RemoveOnHandover: true,
		Install: func() error {
			k.mu.Lock()
			defer k.mu.Unlock()
			k.routes[dev] = true
			k.ops = append(k.ops, "install "+dev)
			return nil
		},
		Remove: func() error {
			k.mu.Lock()
			defer k.mu.Unlock()
			if err := k.failDel[dev]; err != nil {
				return err
			}
			delete(k.routes, dev)
			k.ops = append(k.ops, "remove "+dev)
			return nil
		},
	}
}

func (k *perDeviceKernel) devices() []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	var devs []string
	for dev := range k.routes {
		devs = append(devs, dev)
	}
	return devs
}

func TestRoutesHandoverRemovesTheRouteOfAPerDeviceTable(t *testing.T) {
	routes := NewRoutes()
	kernel := newPerDeviceKernel()

	_, err := routes.Add(keyA, testPrefix, kernel.claim("wt0"))
	require.NoError(t, err)
	_, err = routes.Add(keyB, testPrefix, kernel.claim("wt1"))
	require.NoError(t, err)

	require.NoError(t, routes.Remove(keyA, testPrefix))
	assert.Equal(t, []string{"wt1"}, kernel.devices(), "the route of the previous owner must not stay and win over the new one")
	assert.Equal(t, []string{"install wt0", "install wt1", "remove wt0"}, kernel.ops,
		"the next owner installs before the previous route goes, so the prefix never falls through")

	require.NoError(t, routes.Remove(keyB, testPrefix))
	assert.Empty(t, kernel.devices(), "the last release removes the route")
}

func TestRoutesHandoverReportsARouteThatStays(t *testing.T) {
	routes := NewRoutes()
	kernel := newPerDeviceKernel()
	kernel.failDel["wt0"] = errors.New("access denied")

	_, err := routes.Add(keyA, testPrefix, kernel.claim("wt0"))
	require.NoError(t, err)
	_, err = routes.Add(keyB, testPrefix, kernel.claim("wt1"))
	require.NoError(t, err)

	err = routes.Remove(keyA, testPrefix)
	assert.Error(t, err, "a route that stays shadows the new owner, the caller has to know")
	assert.Equal(t, keyB, routes.prefixes[testPrefix].owner.key, "the claim has moved on regardless")
}
