# Security

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues.** Email them to
[security@clerk.dev](mailto:security@clerk.dev) instead, with:

1. the location and potential impact of the vulnerability, and
2. the steps required to reproduce it (scripts, screenshots and screen captures all help).

If a report needs a credential to demonstrate, describe its shape rather than pasting a real one. We
will evaluate it, and if necessary release a fix or mitigating steps; we will contact you with the
outcome and credit you in the report. Please do not disclose the vulnerability publicly until a fix is
released — once we have published a fix, or declined to address it, you are free to.

## What this tool holds on your computer

- **A device key**, generated on first sign-in. On macOS it lives in the Secure Enclave and on Windows
  in CNG, in both cases with the private half non-extractable: it signs, and it cannot be copied off
  the machine. Elsewhere a file-backed key is used only if you ask for it, and the CLI labels it as
  extractable wherever it shows you the key.
- **A short-lived access token**, bound to that key, stored per API origin and instance. Every request
  carries a fresh proof signed by the key, so a stolen token alone is not enough to use it.
- **Profiles**, which are defaults — an instance and an API origin. They are not credentials.

`clerk-protect keys status` shows where the key lives and whether it can leave the computer.

## What a release is

Release binaries are built with no debug information, no version-control stamp and no builder file
paths, and they link only a reviewed set of modules — the build fails if anything else is linked.
Each release publishes `checksums.txt`; check the archive against it before installing by hand.
Homebrew does that check for you.
