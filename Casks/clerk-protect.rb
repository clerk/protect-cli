# The version and checksums below are rewritten by the release workflow
# (scripts/update-homebrew.py) from the signed packages that release built.
# Change the shape here; never hand-edit the values. Until the first release,
# the placeholders are not installable.
cask "clerk-protect" do
  arch arm: "arm64", intel: "amd64"

  version "0.4.0"
  sha256 arm:   "b3343d6ae4dc70853708362414f52c36bfafbc05733840a870c89877d91652ea",
         intel: "136818f6fd04858e67214e3fa44ac27ea89f0265941f10f5ebf4fb7a9dd1cc46"

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
