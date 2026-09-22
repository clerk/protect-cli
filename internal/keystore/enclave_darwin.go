//go:build darwin

package keystore

// The Secure Enclave binding.
//
// The key is generated inside the Secure Enclave and never leaves it. What is
// persisted is the SEP-wrapped key blob — ciphertext only this Mac's enclave
// can unwrap — so a copied record is inert anywhere else.
//
// Why the CLI persists the blob instead of asking the Keychain to hold the key:
// Keychain-resident keys need the keychain-access-groups entitlement, which a
// binary built from source cannot carry (it gets errSecMissingEntitlement, and
// ad-hoc signing WITH the entitlement is killed at exec). Generating with
// kSecAttrIsPermanent: false never touches the Keychain, and the wrapped blob
// comes back in the key's attributes. That is the same representation CryptoKit
// calls dataRepresentation.
//
// Generation lives here; restoring and signing live in enclave.swift, because
// no Security-framework call restores the same key from its blob.

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -L${SRCDIR} -lclerkprotectenclave -L/usr/lib/swift -Wl,-rpath,/usr/lib/swift
#cgo LDFLAGS: -framework Security -framework Foundation -framework CoreFoundation -framework LocalAuthentication
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <LocalAuthentication/LocalAuthentication.h>
#include <stdlib.h>
#include <string.h>

// The attribute holding the SEP-wrapped blob. Not exported as a constant on
// macOS, but it is the same bytes CryptoKit surfaces as dataRepresentation.
static NSString* const cpBlobAttr = @"toid";

static char* cp_strdup(NSString* s) { return strdup(s ? [s UTF8String] : "unknown error"); }

static void cp_fail(char** outErr, NSString* msg) { if (outErr) *outErr = cp_strdup(msg); }

static void cp_failErr(char** outErr, NSString* op, CFErrorRef err) {
    NSError* e = (__bridge NSError*)err;
    cp_fail(outErr, e ? [NSString stringWithFormat:@"%@: %@ (code %ld)", op, [e localizedDescription], (long)[e code]]
                      : [NSString stringWithFormat:@"%@: unknown error", op]);
}

// The access control. requirePresence makes the ENCLAVE demand Touch ID or the
// device password per signature — not a check the CLI could skip.
static SecAccessControlRef cp_accessControl(int requirePresence, char** outErr) {
    SecAccessControlCreateFlags flags = kSecAccessControlPrivateKeyUsage;
    if (requirePresence) flags |= kSecAccessControlUserPresence;
    CFErrorRef err = NULL;
    SecAccessControlRef ac = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        // ThisDeviceOnly: never synced, never in a backup.
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        flags, &err);
    if (!ac) {
        cp_failErr(outErr, @"SecAccessControlCreateWithFlags", err);
        if (err) CFRelease(err);
    }
    return ac;
}

static SecKeyRef cp_newKey(int requirePresence, char** outErr) {
    SecAccessControlRef ac = cp_accessControl(requirePresence, outErr);
    if (!ac) return NULL;
    NSDictionary* attrs = @{
        (__bridge id)kSecAttrKeyType:       (__bridge id)kSecAttrKeyTypeECSECPrimeRandom,
        (__bridge id)kSecAttrKeySizeInBits: @256,
        (__bridge id)kSecAttrTokenID:       (__bridge id)kSecAttrTokenIDSecureEnclave,
        (__bridge id)kSecPrivateKeyAttrs:   @{
            (__bridge id)kSecAttrIsPermanent:   @NO,
            (__bridge id)kSecAttrAccessControl: (__bridge id)ac,
        },
    };
    CFErrorRef err = NULL;
    SecKeyRef key = SecKeyCreateRandomKey((__bridge CFDictionaryRef)attrs, &err);
    CFRelease(ac);
    if (!key) {
        cp_failErr(outErr, @"SecKeyCreateRandomKey", err);
        if (err) CFRelease(err);
    }
    return key;
}

// cp_available mints a throwaway key to learn whether the enclave works.
// Nothing is persisted.
static int cp_available(char** outErr) {
    @autoreleasepool {
        SecKeyRef k = cp_newKey(0, outErr);
        if (!k) return 0;
        CFRelease(k);
        return 1;
    }
}

static int cp_copyData(CFDataRef src, uint8_t** out, int* outLen) {
    CFIndex n = CFDataGetLength(src);
    uint8_t* buf = malloc((size_t)n);
    if (!buf) return 0;
    memcpy(buf, CFDataGetBytePtr(src), (size_t)n);
    *out = buf;
    *outLen = (int)n;
    return 1;
}

static int cp_generate(int requirePresence, uint8_t** outBlob, int* outBlobLen, char** outErr) {
    @autoreleasepool {
        SecKeyRef key = cp_newKey(requirePresence, outErr);
        if (!key) return 0;
        NSDictionary* attrs = (NSDictionary*)CFBridgingRelease(SecKeyCopyAttributes(key));
        NSData* blob = attrs[cpBlobAttr];
        if (![blob isKindOfClass:[NSData class]] || [blob length] == 0) {
            CFRelease(key);
            cp_fail(outErr, @"the Secure Enclave key exposed no wrapped blob");
            return 0;
        }
        int ok = cp_copyData((__bridge CFDataRef)blob, outBlob, outBlobLen);
        CFRelease(key);
        if (!ok) cp_fail(outErr, @"out of memory copying the key blob");
        return ok;
    }
}

// cp_biometryEnrolled reports whether Touch ID is present with an enrolled
// fingerprint. Inspects only; never prompts.
static int cp_biometryEnrolled(void) {
    @autoreleasepool {
        LAContext* ctx = [[LAContext alloc] init];
        NSError* err = nil;
        return [ctx canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&err] ? 1 : 0;
    }
}

int clerkprotect_enclave_sign(const uint8_t* blob, int blobLen,
                              const uint8_t* digest, int digestLen,
                              const char* prompt, int noInteraction,
                              uint8_t** outSig, int* outSigLen, char** outErr);

int clerkprotect_enclave_public(const uint8_t* blob, int blobLen,
                                uint8_t** outPub, int* outPubLen, char** outErr);
*/
import "C"

import (
	"errors"
	"fmt"
	"sync"
	"unsafe"
)

var enclaveSupported = sync.OnceValue(func() error {
	var cErr *C.char
	if C.cp_available(&cErr) != 0 {
		if cErr != nil {
			C.free(unsafe.Pointer(cErr))
		}
		return nil
	}
	return takeError(cErr, "Secure Enclave unavailable")
})

func takeError(cErr *C.char, fallback string) error {
	if cErr == nil {
		return errors.New(fallback)
	}
	msg := C.GoString(cErr)
	C.free(unsafe.Pointer(cErr))
	return errors.New(msg)
}

func takeBytes(buf *C.uint8_t, n C.int) []byte {
	if buf == nil {
		return nil
	}
	out := C.GoBytes(unsafe.Pointer(buf), n)
	C.free(unsafe.Pointer(buf))
	return out
}

func biometryEnrolled() bool { return C.cp_biometryEnrolled() != 0 }

func enclaveGenerate(requirePresence bool) ([]byte, error) {
	var cBlob *C.uint8_t
	var cBlobLen C.int
	var cErr *C.char
	presence := C.int(0)
	if requirePresence {
		presence = 1
	}
	if C.cp_generate(presence, &cBlob, &cBlobLen, &cErr) == 0 {
		return nil, fmt.Errorf("generate a Secure Enclave key: %w", takeError(cErr, "unknown error"))
	}
	return takeBytes(cBlob, cBlobLen), nil
}

func enclaveSign(blob, digest []byte, prompt string, noInteraction bool) ([]byte, error) {
	if len(blob) == 0 || len(digest) == 0 {
		return nil, errors.New("empty key blob or digest")
	}
	var cPrompt *C.char
	if prompt != "" {
		cPrompt = C.CString(prompt)
		defer C.free(unsafe.Pointer(cPrompt))
	}
	noUI := C.int(0)
	if noInteraction {
		noUI = 1
	}
	var cSig *C.uint8_t
	var cSigLen C.int
	var cErr *C.char
	rc := C.clerkprotect_enclave_sign(
		(*C.uint8_t)(unsafe.Pointer(&blob[0])), C.int(len(blob)),
		(*C.uint8_t)(unsafe.Pointer(&digest[0])), C.int(len(digest)),
		cPrompt, noUI, &cSig, &cSigLen, &cErr)
	if rc != 0 {
		return nil, takeError(cErr, "the Secure Enclave did not sign")
	}
	return takeBytes(cSig, cSigLen), nil
}

func enclavePublic(blob []byte) ([]byte, error) {
	if len(blob) == 0 {
		return nil, errors.New("empty key blob")
	}
	var cPub *C.uint8_t
	var cPubLen C.int
	var cErr *C.char
	if C.clerkprotect_enclave_public((*C.uint8_t)(unsafe.Pointer(&blob[0])), C.int(len(blob)), &cPub, &cPubLen, &cErr) != 0 {
		return nil, fmt.Errorf("read the Secure Enclave public key: %w", takeError(cErr, "unknown error"))
	}
	return takeBytes(cPub, cPubLen), nil
}
