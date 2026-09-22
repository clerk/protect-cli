# The version and checksums below are rewritten by the release workflow
# (scripts/update-homebrew.py) from the signed packages that release built.
# Change the shape here; never hand-edit the values. Until the first release,
# the placeholders are not installable.
cask "clerk-protect" do
  version "0.0.0"

  on_intel do
    sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    url "https://github.com/clerk/protect-cli/releases/download/v#{version}/clerk-protect-v#{version}-darwin-amd64.pkg"
    pkg "clerk-protect-v#{version}-darwin-amd64.pkg"
  end

  on_arm do
    sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    url "https://github.com/clerk/protect-cli/releases/download/v#{version}/clerk-protect-v#{version}-darwin-arm64.pkg"
    pkg "clerk-protect-v#{version}-darwin-arm64.pkg"
  end

  name "Clerk Protect CLI"
  desc "Manage Clerk Protect for your instance from the command line"
  homepage "https://github.com/clerk/protect-cli"

  depends_on macos: ">= :ventura"

  uninstall pkgutil: "com.clerk.protect-cli"

  zap trash: "~/Library/Application Support/clerk-protect"

  caveats <<~EOS
    clerk-protect has been installed to /usr/local/bin/clerk-protect

    To get started, sign in from Protect Labs:
      clerk-protect login
  EOS
end
