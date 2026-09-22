#!/usr/bin/env python3
"""Point the Homebrew cask and formula at a release.

    python3 scripts/update-homebrew.py --version v1.2.3 --dist dist

Reads dist/checksums.txt, then rewrites:

  Casks/clerk-protect.rb    the version, and the sha256 of each signed .pkg
  Formula/clerk-protect.rb  the version, and the url and sha256 of each Linux archive

It fails rather than writing a partial update, because the failure mode is
silent: a cask whose version moved and whose checksum did not fails every
install, and a formula updated for one architecture serves the previous
release's binary to the other, with no error anywhere. Every platform must be
in the release and every line must actually change.
"""

import argparse
import pathlib
import re
import sys

CASK = pathlib.Path("Casks/clerk-protect.rb")
FORMULA = pathlib.Path("Formula/clerk-protect.rb")
RELEASES = "https://github.com/clerk/protect-cli/releases/download"
SHA = r"[0-9a-f]{64}"


def die(message: str) -> None:
    print(f"update-homebrew: {message}", file=sys.stderr)
    raise SystemExit(1)


def replace_once(text: str, pattern: str, repl, what: str, flags: int = 0) -> str:
    new, count = re.subn(pattern, repl, text, flags=flags)
    if count != 1:
        die(f"{what} was replaced {count} times, want once")
    return new


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", required=True, help="the release tag, e.g. v1.2.3")
    ap.add_argument("--dist", default="dist", help="the directory holding checksums.txt")
    args = ap.parse_args()

    tag = args.version if args.version.startswith("v") else "v" + args.version
    number = tag[1:]

    sums_file = pathlib.Path(args.dist) / "checksums.txt"
    if not sums_file.is_file():
        die(f"no {sums_file}")
    sums = {}
    for line in sums_file.read_text().splitlines():
        parts = line.split()
        if len(parts) == 2:
            sums[parts[1].lstrip("*")] = parts[0]

    def checksum(name: str) -> str:
        if name not in sums:
            die(f"{name} is not in {sums_file} — that platform is missing from the release")
        return sums[name]

    # --- The cask: signed macOS packages. Its urls interpolate the version, so
    # only the version and the two checksums change.
    if not CASK.is_file():
        die(f"no {CASK}")
    cask = CASK.read_text()
    before = cask
    cask = replace_once(cask, r'^  version "[^"]*"$', f'  version "{number}"', "the cask version", re.M)
    for block, arch in (("on_intel", "amd64"), ("on_arm", "arm64")):
        sha = checksum(f"clerk-protect-{tag}-darwin-{arch}.pkg")
        cask = replace_once(
            cask,
            r"(  " + block + r' do\n    sha256 ")' + SHA + r'(")',
            lambda m: m.group(1) + sha + m.group(2),
            f"the cask's {block} checksum",
        )
    if cask == before:
        die("the cask did not change — it does not have the shape this script edits")

    # --- The formula: Linux archives.
    if not FORMULA.is_file():
        die(f"no {FORMULA}")
    formula = FORMULA.read_text()
    before = formula
    formula = replace_once(formula, r'^  version "[^"]*"$', f'  version "{number}"', "the formula version", re.M)
    for arch in ("arm64", "amd64"):
        archive = f"clerk-protect-{tag}-linux-{arch}.tar.gz"
        sha = checksum(archive)
        url = f"{RELEASES}/{tag}/{archive}"
        formula = replace_once(
            formula,
            r'(      url ")[^"]*-linux-' + arch + r'\.tar\.gz("\n      sha256 ")' + SHA + r'(")',
            lambda m: m.group(1) + url + m.group(2) + sha + m.group(3),
            f"the formula's linux/{arch} url and checksum",
        )
    if formula == before:
        die("the formula did not change — it does not have the shape this script edits")

    CASK.write_text(cask)
    FORMULA.write_text(formula)
    print(f"update-homebrew: the cask and formula now point at {tag} (2 packages, 2 archives).")


if __name__ == "__main__":
    main()
