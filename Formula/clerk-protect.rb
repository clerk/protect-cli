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
  version "0.6.0"
  license "MIT"

  depends_on :linux

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/clerk/protect-cli/releases/download/v0.6.0/clerk-protect-v0.6.0-linux-arm64.tar.gz"
      sha256 "2d43201976eed76a0a9f349151b9413e69cfcdfffc058635d9d389f0d2246206"
    else
      url "https://github.com/clerk/protect-cli/releases/download/v0.6.0/clerk-protect-v0.6.0-linux-amd64.tar.gz"
      sha256 "342fb96183054f09bbbbeda9edb3aaa15142fdd39de0f638d55b21aba0bf7b73"
    end
  end

  def install
    bin.install "clerk-protect"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/clerk-protect --version")
  end
end
