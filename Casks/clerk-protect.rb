# The version and checksums below are rewritten by the release workflow
# (scripts/update-homebrew.py) from the signed packages that release built.
# Change the shape here; never hand-edit the values. Until the first release,
# the placeholders are not installable.
cask "clerk-protect" do
  arch arm: "arm64", intel: "amd64"

  version "0.6.0"
  sha256 arm:   "ec9bcb56caf9ec1dce9712ee452969f46a66afda603fff7fabae54577ff34c0f",
         intel: "15a1730cbc3e9b179a83703837855588d4a5da3bedb97028bdd65ee84c6bc7d9"

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
