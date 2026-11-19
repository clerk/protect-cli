package auth

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/clerk/protect-cli/internal/dpop"
)

// machineTokenPath is where a machine key asks for a token. Outside the API
// prefix, like the code exchange: it arrives before there is a token.
const machineTokenPath = "/labs/cli/machine-token"

// machineRenewAhead is how long before expiry a machine token is replaced. A
// machine token lives five minutes and cannot be renewed — the next one is
// minted from the key — so this only keeps a request signed now from arriving
// after its token died.
const machineRenewAhead = time.Minute

// MachineSession hands out tokens for an approved machine key. Nothing is
// stored on disk: each process mints its own, which is what a server in a
// fleet of short-lived jobs wants, and what keeps a revoked key from lingering
// in a cache somewhere.
type MachineSession struct {
	Base string
	// Mint signs the mint request: the machine key's builder. With a KMS key
	// this is the run's only call to the KMS.
	Mint *dpop.Builder
	// Proofs signs every API request: this run's in-memory session key, which
	// the token is bound to and which ends with the process.
	Proofs *dpop.Builder
	// Thumbprint is the session key's, the token's binding.
	Thumbprint string
	// InstanceID, when set, is checked by the server against the instance the
	// key was approved for: a mismatch is refused rather than acted on.
	InstanceID string
	HTTP       *http.Client
	// Now is the clock; nil means time.Now.
	Now func() time.Time

	mu    sync.Mutex
	creds *Credentials
}

func (m *MachineSession) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

// Token returns a usable access token, minting a new one when the held one is
// near its end.
func (m *MachineSession) Token(ctx context.Context) (string, error) {
	c, err := m.Credentials(ctx)
	if err != nil {
		return "", err
	}
	return c.AccessToken, nil
}

// Credentials returns the current token's credential, minting one if needed.
func (m *MachineSession) Credentials(ctx context.Context) (*Credentials, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	if m.creds != nil && m.creds.ExpiresAt.Sub(now) > machineRenewAhead {
		return m.creds, nil
	}
	proof, err := m.Mint.MintProof(http.MethodPost, m.Base+machineTokenPath, m.Thumbprint)
	if err != nil {
		return nil, err
	}
	var body any
	if m.InstanceID != "" {
		body = map[string]string{"instance_id": m.InstanceID}
	}
	mintCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	resp, err := postToken(mintCtx, m.HTTP, m.Base+machineTokenPath, body, map[string]string{"DPoP": proof})
	if err != nil {
		return nil, err
	}
	c, err := resp.credentials(m.Base, m.Thumbprint, now)
	if err != nil {
		return nil, err
	}
	m.creds = c
	return c, nil
}

// ReconnectBy is when a long-lived stream should be reopened so the request
// reopening it carries a fresh token.
func (m *MachineSession) ReconnectBy() (time.Time, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.creds == nil {
		return time.Time{}, false
	}
	return m.creds.ExpiresAt.Add(-machineRenewAhead), true
}

// Reconnector is a token source that can say when a long-lived stream should be
// reopened: a person's Session, before its renewal window; a MachineSession,
// before its five minutes end.
type Reconnector interface {
	ReconnectBy() (time.Time, bool)
}
