// Package httperr turns an API error response into the most specific message
// the server sent.
package httperr

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/clerk/protect-cli/internal/textsafe"
)

// Error is a non-2xx API response.
type Error struct {
	Status int
	// Code is the machine-readable error code, when the server sent one —
	// the authorization endpoints do (`invalid_grant`, `authorization_expired`),
	// most others do not.
	Code string
	// Message is the server's own explanation.
	Message string
}

func (e *Error) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("%s (HTTP %d, %s)", e.Message, e.Status, e.Code)
	}
	return fmt.Sprintf("%s (HTTP %d)", e.Message, e.Status)
}

// maxMessage bounds what is shown from a raw body: an HTML error page from a
// proxy is not a message, and a megabyte of it is worse.
const maxMessage = 512

// Parse reads an error body in any of the shapes the API produces, most
// specific first:
//
//  1. an RFC 7807 problem's `detail` — where an invalid rule expression's
//     parser error lives;
//  2. `message`, from `{"message","status"}` and `{"error","message"}` bodies;
//  3. a problem's `title`, when it carried no detail;
//  4. an HTML page, reported as what it means rather than printed: through the
//     console's CDN a refusal (403) arrives as the console's 404 page, so a 404
//     page says "not found, or not permitted" and nothing more;
//  5. the raw text — a plain-text refusal from authentication middleware;
//  6. "HTTP <status>", when nothing was sent at all.
//
// The order matters because a response can carry more than one: a problem body
// has both `title` and `detail`, and the title is only the category.
func Parse(status int, body []byte) *Error {
	e := &Error{Status: status}
	text := strings.TrimSpace(string(body))

	var obj map[string]any
	if json.Unmarshal(body, &obj) == nil && obj != nil {
		str := func(k string) string {
			v, _ := obj[k].(string)
			return strings.TrimSpace(v)
		}
		e.Code = str("error")
		switch {
		case str("detail") != "":
			e.Message = str("detail")
		case str("message") != "":
			e.Message = str("message")
		case str("title") != "":
			e.Message = str("title")
		}
	}
	if e.Message == "" {
		switch {
		case strings.HasPrefix(text, "<") && status == 404:
			e.Message = "not found, or not permitted for this sign-in"
		case strings.HasPrefix(text, "<"):
			e.Message = "the server answered with a web page, not an API response"
		default:
			e.Message = text
			if len(e.Message) > maxMessage {
				e.Message = e.Message[:maxMessage] + "…"
			}
		}
	}
	if e.Message == "" {
		e.Message = fmt.Sprintf("HTTP %d", status)
	}
	// Both are printed to a terminal as they are, so neither may carry a
	// control sequence (see textsafe).
	e.Message = textsafe.Strip(e.Message)
	e.Code = textsafe.Strip(e.Code)
	return e
}
