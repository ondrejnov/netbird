package internal

import (
	"context"
	"sync"
)

type StatusType string

const (
	StatusIdle StatusType = "Idle"

	StatusConnecting     StatusType = "Connecting"
	StatusConnected      StatusType = "Connected"
	StatusNeedsLogin     StatusType = "NeedsLogin"
	StatusLoginFailed    StatusType = "LoginFailed"
	StatusSessionExpired StatusType = "SessionExpired"
)

// CtxInitState setup context state into the context tree.
//
// This function should be used to initialize context before
// CtxGetState will be executed.
func CtxInitState(ctx context.Context) context.Context {
	return CtxWithState(ctx, NewContextState())
}

// NewContextState returns the idle state of one connection.
func NewContextState() *ContextState {
	return &ContextState{status: StatusIdle}
}

// CtxWithState returns a context whose CtxGetState resolves to state, for a caller that
// owns the state and starts a connection under it.
func CtxWithState(ctx context.Context, state *ContextState) context.Context {
	return context.WithValue(ctx, stateCtx, state)
}

// CtxGetState object to get/update state/errors of process.
func CtxGetState(ctx context.Context) *ContextState {
	return ctx.Value(stateCtx).(*ContextState)
}

// ContextState is the status and the last error of one connection.
type ContextState struct {
	err      error
	status   StatusType
	mutex    sync.Mutex
	onChange func()
}

// SetOnChange installs a callback fired after every successful Set. Used by
// the daemon to wire the status recorder's notifyStateChange so any
// state.Set in the connect/login paths pushes a fresh snapshot to
// SubscribeStatus subscribers without each callsite having to opt in.
// The callback runs outside the ContextState mutex to avoid a lock-order
// dependency with the recorder's stateChangeMux.
func (c *ContextState) SetOnChange(fn func()) {
	c.mutex.Lock()
	c.onChange = fn
	c.mutex.Unlock()
}

func (c *ContextState) Set(update StatusType) {
	c.mutex.Lock()
	c.status = update
	c.err = nil
	cb := c.onChange
	c.mutex.Unlock()

	if cb != nil {
		cb()
	}
}

func (c *ContextState) Status() (StatusType, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.err != nil {
		return "", c.err
	}

	return c.status, nil
}

// CurrentStatus returns the last status set via Set, ignoring any wrapped
// error. Use when the status is needed for reporting purposes (e.g. the
// status snapshot stream) and a transient wrapped error from a retry loop
// shouldn't blank out the underlying status.
func (c *ContextState) CurrentStatus() StatusType {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	return c.status
}

func (c *ContextState) Wrap(err error) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.err = err
	return err
}

type stateKey int

var stateCtx stateKey
