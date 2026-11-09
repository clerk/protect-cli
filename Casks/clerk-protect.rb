# The version and checksums below are rewritten by the release workflow
# (scripts/update-homebrew.py) from the signed packages that release built.
# Change the shape here; never hand-edit the values. Until the first release,
# the placeholders are not installable.
cask "clerk-protect" do
  arch arm: "arm64", intel: "amd64"

  version "0.5.0"
  sha256 arm:   "c693c1a733b134f96c83d9eacbfb3e9fedd762c5c3b860db7a7658dd755d671b",
         intel: "412776c3c7109cd5b59b7d0962cb3dbab92ceb9301056fb5540d87b14f1c5701"

  url "https://github.com/clerk/protect-cli/releases/download/v#{version}/clerk-protect-v#{version}-darwin-#{arch}.pkg"
  name "Clerk Protect CLI"
  desc "Manage Clerk Protect for your instance from the command-line"
  homepage "https://github.com/clerk/protect-cli"

  depends_on macos: :ventura

  pkg "clerk-protect-v#{version}-darwin-#{arch}.pkg"

  uninstall pkgutil: "com.clerk.protect-cli"

  zap trash: "~/Library/Application Support/clerk-protect"

  caveats <<~EOS
    clerk-protect has been installed to /usr/local/bin/clerk-protect

    To get started, sign in from Protect Labs:
      clerk-protect login
  EOS
end
