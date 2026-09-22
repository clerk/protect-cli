# The version and checksums below are rewritten by the release workflow
# (scripts/update-homebrew.py) from the signed packages that release built.
# Change the shape here; never hand-edit the values. Until the first release,
# the placeholders are not installable.
cask "clerk-protect" do
  arch arm: "arm64", intel: "amd64"

  version "0.3.1"
  sha256 arm:   "23bb1b54fb5fd7c0cd56360a1647ec7c014841e9db8b650ddf546c6c984605ef",
         intel: "9e375960d928ffe307ab0ddbb599b1b99621080bfa16c2dd3dbe97a32f1f968d"

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
