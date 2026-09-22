# Linux only. On macOS, install the cask instead — a package signed with
# Clerk's Developer ID and notarized by Apple:
#
#   brew install --cask clerk-protect
#
# The version, urls and checksums below are rewritten by the release workflow
# (scripts/update-homebrew.py) from the archives that release built. Change the
# shape here; never hand-edit the values. Until the first release, the
# placeholders are not installable.
class ClerkProtect < Formula
  desc "Manage Clerk Protect for your instance from the command-line"
  homepage "https://github.com/clerk/protect-cli"
  version "0.0.0"
  license "MIT"

  depends_on :linux

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/clerk/protect-cli/releases/download/v0.0.0/clerk-protect-v0.0.0-linux-arm64.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000001"
    else
      url "https://github.com/clerk/protect-cli/releases/download/v0.0.0/clerk-protect-v0.0.0-linux-amd64.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000002"
    end
  end

  def install
    bin.install "clerk-protect"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/clerk-protect --version")
  end
end
