// Package term answers one question: is this file descriptor a terminal?
//
// Asked of the terminal driver, not of the file's mode. A character device is
// not a terminal — /dev/null is one, and it is what cron and most service
// managers hand a job as stdin — so "is a character device" would put a
// confirmation prompt in front of a job that can never answer it, instead of
// refusing the way a script is told it will be.
//
// Standard library only: an ioctl for the terminal settings on unix, the
// console mode on Windows. Where neither is known, nothing is a terminal, which
// is the safe answer — it refuses rather than prompts.
package term
