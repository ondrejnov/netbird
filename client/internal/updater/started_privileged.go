//go:build privileged

package updater

// Started reports whether the update loop has been started. It exists for the privileged tests.
func (m *Manager) Started() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cancel != nil
}
