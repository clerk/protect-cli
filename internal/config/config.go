// Package config resolves where clerk-protect keeps its state and which API it
// talks to.
package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

const (
	// EnvConfigDir relocates every file this CLI writes: the device key record,
	// and the cached credentials.
	//
	// A NAME OF ITS OWN. Other Clerk tools read other variables, and a parent
	// process that sets one of those must never retarget this binary's key.
	EnvConfigDir = "CLERK_PROTECT_CONFIG_DIR"

	// EnvAPIURL overrides the API origin, for testing against a non-production
	// deployment. The --api-url flag wins over it.
	EnvAPIURL = "CLERK_PROTECT_API_URL"

	// DefaultAPIBase is the one origin compiled into the binary.
	DefaultAPIBase = "https://dashboard.protect.clerk.com"
)

// Dir is the directory clerk-protect reads and writes. It is created on first
// write, never here.
func Dir() (string, error) {
	if dir := strings.TrimSpace(os.Getenv(EnvConfigDir)); dir != "" {
		return filepath.Clean(dir), nil
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("find the user configuration directory (set %s): %w", EnvConfigDir, err)
	}
	return filepath.Join(base, "clerk-protect"), nil
}

// Where an API origin came from, as APIBase reports it.
const (
	SourceFlag    = "--api-url"
	SourceEnv     = EnvAPIURL
	SourceProfile = "profile"
	SourceDefault = "default"
)

// APIBase resolves the API origin — the flag, then the environment, then a
// profile's origin, then the default — and says which of them it came from.
//
// The profile comes after the environment variable, as a configuration file
// does after the environment for most tools: CLERK_PROTECT_API_URL exists for
// pointing a whole shell at a test deployment, and a profile saved for everyday
// use must not quietly override that.
func APIBase(flag, profileURL string) (base, source string, err error) {
	if strings.TrimSpace(flag) != "" {
		base, err = ParseAPIBase(flag)
		return base, SourceFlag, err
	}
	if env := strings.TrimSpace(os.Getenv(EnvAPIURL)); env != "" {
		base, err = ParseAPIBase(env)
		return base, SourceEnv, err
	}
	if strings.TrimSpace(profileURL) != "" {
		base, err = ParseAPIBase(profileURL)
		return base, SourceProfile, err
	}
	return DefaultAPIBase, SourceDefault, nil
}

// ParseAPIBase checks an API origin and returns it in its normal form.
//
// An ORIGIN, never a URL with a path: every request signs `origin + path`, and
// a base carrying a path of its own would sign a URL the server never computes.
// https is required, except for a loopback host — a local development server —
// because a credential bound to this machine's key is still a credential, and
// cleartext would hand every request to the network.
func ParseAPIBase(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("the API URL is empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid API URL %q: %w", raw, err)
	}
	if u.Host == "" {
		return "", fmt.Errorf("invalid API URL %q: no host", raw)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", fmt.Errorf("invalid API URL %q: give an origin like https://host, with no path, query or credentials", raw)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopback(u.Hostname()) {
			return "", errors.New("the API URL must use https (plain http is accepted only for a loopback address)")
		}
	default:
		return "", fmt.Errorf("invalid API URL %q: scheme must be https", raw)
	}
	return u.Scheme + "://" + u.Host, nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
