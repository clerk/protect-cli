package cli

import (
	"testing"
	"time"

	"github.com/clerk/protect-cli/internal/auth"
)

// A stream is closed from this side before its token expires, so the request
// reopening it renews. When the renewal that was due has already failed — the
// reconnect time is behind us and the old token is still in use — the stream must
// reopen soon and try again WHILE THE TOKEN IS STILL LIVE, because the server
// renews only a valid token — whenever more than the one-second retry floor
// remains. A retry scheduled at the expiry itself is no retry.
func TestTraceDeadline_retriesWhileTheTokenCanStillBeRenewed(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	// reconnectBy for a token expiring at now+d.
	expiringIn := func(d time.Duration) time.Time { return now.Add(d - auth.RenewFloor) }

	for name, tc := range map[string]struct {
		reconnectBy time.Time
		want        time.Time
	}{
		"reconnect time ahead": {
			reconnectBy: now.Add(10 * time.Minute),
			want:        now.Add(10 * time.Minute),
		},
		"renewal due and not done, token has time left": {
			reconnectBy: expiringIn(auth.RenewFloor - time.Second),
			want:        now.Add(traceRenewRetry),
		},
		"renewal due and not done, ten seconds left": {
			reconnectBy: expiringIn(10 * time.Second),
			want:        now.Add(10*time.Second - traceRenewMargin),
		},
		"renewal due and not done, three seconds left": {
			reconnectBy: expiringIn(3 * time.Second),
			want:        now.Add(traceRetryFloor),
		},
	} {
		t.Run(name, func(t *testing.T) {
			got := traceDeadline(now, tc.reconnectBy)
			if !got.Equal(tc.want) {
				t.Fatalf("deadline %s, want %s", got.Sub(now), tc.want.Sub(now))
			}
			// The property itself, not only the arithmetic: with more than the
			// retry floor left, the retry lands while the token is still live.
			expiry := tc.reconnectBy.Add(auth.RenewFloor)
			if expiry.Sub(now) > traceRetryFloor && !got.Before(expiry) {
				t.Fatalf("deadline %s is not before the token's expiry %s", got.Sub(now), expiry.Sub(now))
			}
		})
	}
}
