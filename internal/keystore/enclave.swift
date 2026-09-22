// Secure Enclave key restore and signing for clerk-protect.
//
// WHY SWIFT: a Secure Enclave key that survives across runs has to be persisted
// somehow, and the Keychain is not available to a binary without a signing
// identity carrying the keychain-access-groups entitlement. So the CLI stores
// the SEP-wrapped key blob itself. Generating the key and reading that blob is
// possible from the Security framework through cgo (enclave_darwin.go);
// RESTORING the same key from the blob is not — SecKeyCreateWithData silently
// returns a different key. CryptoKit's
// SecureEnclave.P256.Signing.PrivateKey(dataRepresentation:) restores the same
// key, and CryptoKit is Swift-only.
//
// Every symbol here is public, documented API.

import CryptoKit
import Foundation
import LocalAuthentication

/// crypto.Signer hands the Go side a pre-computed 32-byte digest, but
/// CryptoKit's `signature(for: some DataProtocol)` hashes its argument, which
/// would sign SHA-256 twice. A custom `Digest` conformance reaches the
/// digest-based overload with the raw bytes.
private struct RawSHA256Digest: Digest {
    static var byteCount: Int { 32 }
    let bytes: [UInt8]

    func makeIterator() -> Array<UInt8>.Iterator { bytes.makeIterator() }

    func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try bytes.withUnsafeBytes(body)
    }

    var description: String { "RawSHA256Digest" }
}

private func emit(_ data: Data, _ out: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
                  _ len: UnsafeMutablePointer<Int32>) {
    // malloc, not Swift allocation: the Go side frees this with free().
    let buf = malloc(data.count)!.assumingMemoryBound(to: UInt8.self)
    data.copyBytes(to: buf, count: data.count)
    out.pointee = buf
    len.pointee = Int32(data.count)
}

/// ONE authentication context per process, for a presence-protected key.
///
/// Every request this CLI makes is signed, and one command can make several —
/// a renewal, then the request. A fresh context per signature would put a
/// Touch ID prompt in front of each. Reusing the context lets one
/// authentication cover the whole command, which is what a person running it
/// expects, while a new process always asks again.
nonisolated(unsafe) private var sharedContext: LAContext?
private let sharedContextLock = NSLock()

private func authenticationContext(prompt: UnsafePointer<CChar>?, noInteraction: Int32) -> LAContext? {
    if noInteraction != 0 {
        // "Would this key prompt?" answered without a dialog: a
        // presence-gated key refuses instead of asking.
        let ctx = LAContext()
        ctx.interactionNotAllowed = true
        return ctx
    }
    guard let prompt else { return nil }
    sharedContextLock.lock()
    defer { sharedContextLock.unlock() }
    if let ctx = sharedContext { return ctx }
    let ctx = LAContext()
    ctx.localizedReason = String(cString: prompt)
    sharedContext = ctx
    return ctx
}

private func restore(_ blob: Data, prompt: UnsafePointer<CChar>?,
                     noInteraction: Int32) throws -> SecureEnclave.P256.Signing.PrivateKey {
    try SecureEnclave.P256.Signing.PrivateKey(
        dataRepresentation: blob,
        authenticationContext: authenticationContext(prompt: prompt, noInteraction: noInteraction))
}

/// Signs a 32-byte SHA-256 digest and returns an ASN.1 DER ECDSA signature —
/// the encoding *ecdsa.PrivateKey produces, so the Go side needs no conversion.
@_cdecl("clerkprotect_enclave_sign")
public func clerkprotect_enclave_sign(
    _ blob: UnsafePointer<UInt8>, _ blobLen: Int32,
    _ digest: UnsafePointer<UInt8>, _ digestLen: Int32,
    _ prompt: UnsafePointer<CChar>?, _ noInteraction: Int32,
    _ outSig: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    _ outSigLen: UnsafeMutablePointer<Int32>,
    _ outErr: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>
) -> Int32 {
    guard digestLen == 32 else {
        outErr.pointee = strdup("expected a 32-byte SHA-256 digest, got \(digestLen)")
        return -1
    }
    do {
        let key = try restore(Data(bytes: blob, count: Int(blobLen)),
                              prompt: prompt, noInteraction: noInteraction)
        let raw = Array(UnsafeBufferPointer(start: digest, count: Int(digestLen)))
        let sig = try key.signature(for: RawSHA256Digest(bytes: raw))
        emit(sig.derRepresentation, outSig, outSigLen)
        return 0
    } catch {
        outErr.pointee = strdup("\(error)")
        return -2
    }
}

/// Returns the X9.63 uncompressed public point for a stored blob. Reading the
/// public half needs no authentication, so this never prompts.
@_cdecl("clerkprotect_enclave_public")
public func clerkprotect_enclave_public(
    _ blob: UnsafePointer<UInt8>, _ blobLen: Int32,
    _ outPub: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    _ outPubLen: UnsafeMutablePointer<Int32>,
    _ outErr: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>
) -> Int32 {
    do {
        let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: Data(bytes: blob, count: Int(blobLen)))
        emit(key.publicKey.x963Representation, outPub, outPubLen)
        return 0
    } catch {
        outErr.pointee = strdup("\(error)")
        return -2
    }
}
