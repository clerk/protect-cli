# Contributing

## Where the code is developed

This repository is where `clerk-protect` is **published**. The source is exported here from Clerk's
own repository, where it is developed and reviewed beside the API it talks to.

That has one consequence worth saying plainly: **a pull request opened here cannot be merged here.**
The export would overwrite it on the next release. Pull requests are still welcome and still read —
a change we take is re-landed internally and arrives in the next export, and we will say so on the
pull request when that happens.

Issues are the better path for most things, and they are read by the people who maintain the CLI.

## Reporting a problem

Please include:

- what you ran, with the flags (redact instance ids and anything that looks like a token),
- what happened, and what you expected instead,
- `clerk-protect --version`, your operating system, and how you installed it.

If the CLI printed an error, the exact text helps more than a paraphrase. For anything involving a
credential, a token or a key, use the security process in [SECURITY.md](SECURITY.md) rather than an
issue.

## Building it yourself

```bash
make test        # unit tests
make lint        # golangci-lint, if you have it
make install     # build, check and install onto your PATH
```

`make`, not a bare `go build`: on macOS the Secure Enclave support is Swift and has to be compiled
first, and `make` builds the way a release is built — no debug information, no builder paths — and
checks the artifact before installing it.

A note on that check: `make binary` runs `tools/guardscan`, which verifies that the binary links only
reviewed modules and carries no debug information or version-control stamp. It also scans for a list
of strings that must never appear in a released binary. That list is not in this repository, so the
scan you run locally reports that it did not run — `guardscan` says so on its result line rather than
printing a clean scan it never made. A release is scanned with the list when this repository holds it
as the `FORBIDDEN_TERMS` secret, and says so when it does not.

## Releasing

For maintainers. A release is a tag on `main`:

```bash
git tag v1.2.3 && git push origin v1.2.3
```

`.github/workflows/release.yml` then builds Linux and Windows on Linux, and builds, signs and
notarizes both macOS packages on a Mac — the Secure Enclave support has to be compiled there. It
publishes the release with `checksums.txt` and opens a pull request pointing the Homebrew cask and
formula at it — merge that, and `brew upgrade` finds the release. macOS
ships only as the signed package, so the release waits for both packages rather than publishing
without them.

To test the build and signing without publishing anything, run the workflow by hand on `main` with
`skip_release` left on; the signed packages are kept as workflow artifacts for a day. The signing
certificates live in the `release` environment, which only `main` and `v*.*.*` tags can use.
`scripts/export-certs-for-github.sh` walks through exporting them when they need replacing.
