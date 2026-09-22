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
  version "0.3.0"
  license "MIT"

  depends_on :linux

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/clerk/protect-cli/releases/download/v0.3.0/clerk-protect-v0.3.0-linux-arm64.tar.gz"
      sha256 "72ad3af4bc3ee17982ba25d27a9dfb430b3ae18be8d824459d781403b51030c1"
    else
      url "https://github.com/clerk/protect-cli/releases/download/v0.3.0/clerk-protect-v0.3.0-linux-amd64.tar.gz"
      sha256 "a0d11f396644ab9f07bfc84d8386bc9f482336cdd9a586a079d4acb2d97887fa"
    end
  end

  def install
    bin.install "clerk-protect"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/clerk-protect --version")
  end
end
