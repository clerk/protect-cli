# The version and checksums below are rewritten by the release workflow
# (scripts/update-homebrew.py) from the signed packages that release built.
# Change the shape here; never hand-edit the values. Until the first release,
# the placeholders are not installable.
cask "clerk-protect" do
  arch arm: "arm64", intel: "amd64"

  version "0.3.0"
  sha256 arm:   "b299e8939ac904299b9f7d25e3099ab2223dcfe50ff604a748e411441955a1c7",
         intel: "94c592c64034c0efe7cfb752c43be6ff3711ac08b81c1f0d60af6f2edbfbd9ac"

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
