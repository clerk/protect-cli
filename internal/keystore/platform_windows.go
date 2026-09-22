//go:build windows

package keystore

// The Windows key store: CNG through ncrypt.dll.
//
// The key is created by a key storage provider and persisted by it, under a
// name; the CLI keeps only a small record saying which provider and which name.
// Two providers, tried in order:
//
//	Microsoft Platform Crypto Provider       the TPM. The key is generated in the
//	                                         chip and cannot leave it.
//	Microsoft Software Key Storage Provider  no usable TPM. The key is created
//	                                         with an export policy that forbids
//	                                         export, so the operating system
//	                                         will not hand it out — but it is
//	                                         protected by the user's Windows
//	                                         secrets, not by hardware, and is
//	                                         labelled so.
//
// THE FALLBACK IS NARROW. A software key is created only when the TPM provider
// cannot be opened or answers that it cannot hold this key at all (no TPM, its
// service not running, no P-256). Any other error from a TPM that exists is
// reported: a transient fault must not quietly leave a machine that has a TPM
// with a weaker key for good.
//
// Pure Go over the standard library's syscall package: no cgo, so a Windows
// binary cross-compiles from anywhere.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/clerk/protect-cli/internal/dpop"
	"github.com/clerk/protect-cli/internal/fsutil"
)

const (
	platformBackendName = "cng"
	cngRecordName       = "device-key.json"
	cngRecordV1         = 1
	keyNamePrefix       = "clerk-protect-device-key-"

	providerPlatform = "Microsoft Platform Crypto Provider"
	providerSoftware = "Microsoft Software Key Storage Provider"

	algECDSAP256       = "ECDSA_P256"
	blobECCPublic      = "ECCPUBLICBLOB"
	propExportPolicy   = "Export Policy"
	eccPublicP256Magic = 0x31534345 // "ECS1"
)

// The SECURITY_STATUS and TBS result codes this file acts on (winerror.h).
const (
	nteBadAlgID          = 0x80090008
	nteExists            = 0x8009000F
	nteBadKeyset         = 0x80090016 // the named key does not exist
	nteProviderDLLFail   = 0x8009001D
	nteProvDLLNotFound   = 0x8009001E
	nteNotSupported      = 0x80090029
	nteDeviceNotReady    = 0x80090030
	nteDeviceNotFound    = 0x80090035
	tbsServiceNotRunning = 0x80284008
	tbsTPMNotFound       = 0x8028400F
	tbsServiceDisabled   = 0x80284010
	tpmPCPDeviceNotReady = 0x80290401 // TPM_E_PCP_DEVICE_NOT_READY; 0x80290201 is TBSIMP_E_CLEANUP_FAILED
)

// The ncrypt.dll exports used here.
const (
	procOpenStorageProvider = "NCryptOpenStorageProvider"
	procCreatePersistedKey  = "NCryptCreatePersistedKey"
	procOpenKey             = "NCryptOpenKey"
	procSetProperty         = "NCryptSetProperty"
	procFinalizeKey         = "NCryptFinalizeKey"
	procExportKey           = "NCryptExportKey"
	procSignHash            = "NCryptSignHash"
	procDeleteKey           = "NCryptDeleteKey"
	procFreeObject          = "NCryptFreeObject"
)

const loadLibrarySearchSystem32 = 0x00000800 // LOAD_LIBRARY_SEARCH_SYSTEM32

// loadNcrypt loads ncrypt.dll from System32 and nowhere else.
//
// A plain LoadLibrary searches the executable's own directory first, so an
// ncrypt.dll planted beside a downloaded clerk-protect.exe would be asked to
// sign every request. The standard library pins only the DLLs it uses itself to
// System32, and ncrypt.dll is not one of them. kernel32.dll is, so its
// LoadLibraryExW is called with the System32-only flag, the same call the
// standard library makes for its own.
//
// Not golang.org/x/sys/windows, whose NewLazySystemDLL does exactly this: its
// generated table of Win32 export names ships whole in every binary that
// imports the package, and one of those names (GetIpForwardEntry2) contains a
// word the release guard in internal/guard forbids in this binary.
var loadNcrypt = sync.OnceValues(func() (*syscall.DLL, error) {
	loadLibraryEx := syscall.NewLazyDLL("kernel32.dll").NewProc("LoadLibraryExW")
	if err := loadLibraryEx.Find(); err != nil {
		return nil, err
	}
	name, err := syscall.UTF16PtrFromString("ncrypt.dll")
	if err != nil {
		return nil, err
	}
	h, _, callErr := loadLibraryEx.Call(uintptr(unsafe.Pointer(name)), 0, loadLibrarySearchSystem32)
	if h == 0 {
		return nil, fmt.Errorf("load ncrypt.dll from System32: %w", callErr)
	}
	return &syscall.DLL{Name: "ncrypt.dll", Handle: syscall.Handle(h)}, nil
})

// cngError is a SECURITY_STATUS from ncrypt.dll.
type cngError uint32

func (e cngError) Error() string { return fmt.Sprintf("Windows key storage error 0x%08X", uint32(e)) }

// errProviderUnavailable wraps a failure to open a key storage provider at all.
var errProviderUnavailable = errors.New("the key storage provider could not be opened")

// call invokes an ncrypt export by name. A missing DLL or export is an error,
// not a panic.
//
// Callers pass pointers converted to uintptr, several of them to local
// out-parameters. uintptrescapes keeps what they point at alive and in place
// until the call returns, as it does for syscall's own Call; without it a
// stack that grows inside this function could move a variable ncrypt is about
// to write through.
//
//go:uintptrescapes
func call(name string, args ...uintptr) error {
	dll, err := loadNcrypt()
	if err != nil {
		return fmt.Errorf("Windows key storage is unavailable: %w", err)
	}
	proc, err := dll.FindProc(name)
	if err != nil {
		return fmt.Errorf("Windows key storage is unavailable: %w", err)
	}
	r, _, _ := proc.Call(args...)
	if r != 0 {
		return cngError(uint32(r))
	}
	return nil
}

func utf16(s string) *uint16 {
	p, err := syscall.UTF16PtrFromString(s)
	if err != nil {
		// Only a string with a NUL in it fails, and every string here is a
		// constant or a name this file builds.
		panic(err)
	}
	return p
}

// platformCannotHoldKey reports whether an error from the TPM provider means it
// cannot hold this key at all — no TPM, its service stopped or disabled, no
// P-256 support — as opposed to a fault in a TPM that can.
func platformCannotHoldKey(err error) bool {
	var ce cngError
	if !errors.As(err, &ce) {
		return false
	}
	switch uint32(ce) {
	case nteBadAlgID, nteNotSupported, nteDeviceNotReady, nteDeviceNotFound, nteProviderDLLFail, nteProvDLLNotFound,
		tbsServiceNotRunning, tbsTPMNotFound, tbsServiceDisabled, tpmPCPDeviceNotReady:
		return true
	}
	return false
}

type cngRecord struct {
	Version int `json:"version"`
	// Backend is written for a person reading the file and never read back: the
	// backend is decided by the provider the key is opened through.
	Backend   string    `json:"backend"`
	Provider  string    `json:"provider"`
	KeyName   string    `json:"key_name"`
	CreatedAt time.Time `json:"created_at"`
}

// backendFor is the backend a provider's keys live in. What `keys status` shows
// comes from here — from the provider the key was actually opened through — so
// an edited record cannot label a software key as a TPM one.
func backendFor(provider string) (Backend, bool) {
	switch provider {
	case providerPlatform:
		return BackendTPM, true
	case providerSoftware:
		return BackendSoftware, true
	default:
		return "", false
	}
}

func readRecord(dir string) (cngRecord, error) {
	data, err := os.ReadFile(filepath.Join(dir, cngRecordName))
	if errors.Is(err, os.ErrNotExist) {
		return cngRecord{}, ErrNoKey
	}
	if err != nil {
		return cngRecord{}, err
	}
	var rec cngRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return cngRecord{}, fmt.Errorf("read the device key record: %w", err)
	}
	if _, ok := backendFor(rec.Provider); !ok {
		return cngRecord{}, fmt.Errorf("the device key record names an unknown provider %q", rec.Provider)
	}
	if !strings.HasPrefix(rec.KeyName, keyNamePrefix) {
		return cngRecord{}, fmt.Errorf("the device key record names a key this program did not create: %q", rec.KeyName)
	}
	return rec, nil
}

type cngDevice struct {
	mu      sync.Mutex
	prov    uintptr
	key     uintptr
	pub     *ecdsa.PublicKey
	thumb   string
	backend Backend
}

func (d *cngDevice) Public() crypto.PublicKey { return d.pub }
func (d *cngDevice) Backend() Backend         { return d.backend }
func (d *cngDevice) Thumbprint() string       { return d.thumb }
func (d *cngDevice) Protection() string       { return "" }

func (d *cngDevice) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts == nil || opts.HashFunc() != crypto.SHA256 || len(digest) != sha256.Size {
		return nil, errors.New("keystore: Windows key storage signs SHA-256 digests only here")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	sig := make([]byte, 64)
	var n uint32
	// No padding info for ECDSA. CNG returns the raw r||s form.
	if err := call(procSignHash, d.key, 0,
		uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)),
		uintptr(unsafe.Pointer(&sig[0])), uintptr(len(sig)),
		uintptr(unsafe.Pointer(&n)), 0); err != nil {
		return nil, fmt.Errorf("sign with the device key: %w", err)
	}
	if n != 64 {
		return nil, fmt.Errorf("Windows key storage returned a %d-byte signature, want 64", n)
	}
	return dpop.JOSEToDER(sig)
}

// keyName is scoped to the configuration directory, so two directories — two
// test runs, two users of one account — never share a key by accident.
func keyName(dir string) string {
	sum := sha256.Sum256([]byte(filepath.Clean(dir)))
	return keyNamePrefix + hex.EncodeToString(sum[:6])
}

func openProvider(name string) (uintptr, error) {
	var h uintptr
	if err := call(procOpenStorageProvider, uintptr(unsafe.Pointer(&h)), uintptr(unsafe.Pointer(utf16(name))), 0); err != nil {
		return 0, fmt.Errorf("%w: %s: %w", errProviderUnavailable, name, err)
	}
	return h, nil
}

func openKey(prov uintptr, name string) (uintptr, error) {
	var key uintptr
	if err := call(procOpenKey, prov, uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(utf16(name))), 0, 0); err != nil {
		return 0, err
	}
	return key, nil
}

func freeObject(h uintptr) {
	if h != 0 {
		_ = call(procFreeObject, h)
	}
}

func exportPublic(key uintptr) (*ecdsa.PublicKey, error) {
	blobType := utf16(blobECCPublic)
	var size uint32
	if err := call(procExportKey, key, 0, uintptr(unsafe.Pointer(blobType)), 0, 0, 0, uintptr(unsafe.Pointer(&size)), 0); err != nil {
		return nil, fmt.Errorf("read the device public key: %w", err)
	}
	if size < 8+64 {
		return nil, fmt.Errorf("device public key blob is %d bytes", size)
	}
	buf := make([]byte, size)
	if err := call(procExportKey, key, 0, uintptr(unsafe.Pointer(blobType)), 0,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(size), uintptr(unsafe.Pointer(&size)), 0); err != nil {
		return nil, fmt.Errorf("read the device public key: %w", err)
	}
	// BCRYPT_ECCKEY_BLOB: little-endian magic and coordinate length, then X, Y.
	magic := binary.LittleEndian.Uint32(buf[0:4])
	coord := binary.LittleEndian.Uint32(buf[4:8])
	if magic != eccPublicP256Magic || coord != 32 || len(buf) < 8+64 {
		return nil, fmt.Errorf("device public key is not a P-256 key (magic 0x%08X, %d-byte coordinates)", magic, coord)
	}
	point := append([]byte{4}, buf[8:8+64]...)
	return ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
}

func newCNGDevice(prov, key uintptr, backend Backend) (*cngDevice, error) {
	pub, err := exportPublic(key)
	if err != nil {
		return nil, err
	}
	thumb, err := dpop.Thumbprint(pub)
	if err != nil {
		return nil, err
	}
	return &cngDevice{prov: prov, key: key, pub: pub, thumb: thumb, backend: backend}, nil
}

func platformOpen(dir string) (Device, error) {
	rec, err := readRecord(dir)
	if err != nil {
		return nil, err
	}
	backend, _ := backendFor(rec.Provider)
	prov, err := openProvider(rec.Provider)
	if err != nil {
		return nil, err
	}
	key, err := openKey(prov, rec.KeyName)
	if err != nil {
		freeObject(prov)
		if errors.Is(err, cngError(nteBadKeyset)) {
			return nil, ErrNoKey
		}
		return nil, fmt.Errorf("open the device key: %w", err)
	}
	d, err := newCNGDevice(prov, key, backend)
	if err != nil {
		freeObject(key)
		freeObject(prov)
		return nil, err
	}
	return d, nil
}

// createKey creates and finalizes a persisted P-256 key under name.
func createKey(prov uintptr, name string, software bool) (uintptr, error) {
	var key uintptr
	if err := call(procCreatePersistedKey, prov, uintptr(unsafe.Pointer(&key)),
		uintptr(unsafe.Pointer(utf16(algECDSAP256))), uintptr(unsafe.Pointer(utf16(name))), 0, 0); err != nil {
		return 0, err
	}
	if software {
		// Explicitly forbid export, before the key exists. Set on the software
		// provider only: a TPM key cannot be exported whatever the policy says,
		// and the TPM provider may refuse the property.
		policy := uint32(0)
		if err := call(procSetProperty, key, uintptr(unsafe.Pointer(utf16(propExportPolicy))),
			uintptr(unsafe.Pointer(&policy)), unsafe.Sizeof(policy), 0); err != nil {
			freeObject(key)
			return 0, fmt.Errorf("forbid export of the device key: %w", err)
		}
	}
	if err := call(procFinalizeKey, key, 0); err != nil {
		freeObject(key)
		return 0, err
	}
	return key, nil
}

// createIn creates the key in one provider, or opens the key this directory
// already has there.
//
// NTE_EXISTS means a key under this directory's name is already in the
// provider — its record was lost, or never written after a crash. That key is
// opened and used. Falling back to another provider on it would put a second,
// weaker key beside a TPM key that is still there.
func createIn(providerName, name string, software bool) (uintptr, uintptr, error) {
	prov, err := openProvider(providerName)
	if err != nil {
		return 0, 0, err
	}
	key, err := createKey(prov, name, software)
	if errors.Is(err, cngError(nteExists)) {
		key, err = openKey(prov, name)
		if err != nil {
			err = fmt.Errorf("open the device key already in %s: %w", providerName, err)
		}
	}
	if err != nil {
		freeObject(prov)
		return 0, 0, err
	}
	return prov, key, nil
}

func platformCreate(dir string) (Device, error) {
	name := keyName(dir)
	providerName := providerPlatform
	prov, key, err := createIn(providerPlatform, name, false)
	if err != nil {
		if !errors.Is(err, errProviderUnavailable) && !platformCannotHoldKey(err) {
			return nil, fmt.Errorf("create the device key in the TPM: %w", err)
		}
		providerName = providerSoftware
		prov, key, err = createIn(providerSoftware, name, true)
		if err != nil {
			return nil, fmt.Errorf("%w: this computer has no usable TPM, and Windows key storage refused too: %v", ErrUnsupported, err)
		}
	}
	backend, _ := backendFor(providerName)
	d, err := newCNGDevice(prov, key, backend)
	if err != nil {
		freeObject(key)
		freeObject(prov)
		return nil, err
	}
	rec := cngRecord{Version: cngRecordV1, Backend: string(backend), Provider: providerName, KeyName: name, CreatedAt: time.Now().UTC()}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := fsutil.WriteFileAtomic(filepath.Join(dir, cngRecordName), data, 0o600); err != nil {
		return nil, err
	}
	return d, nil
}

// platformDelete deletes the key the record names, from the provider it names.
// With no record there is nothing this directory knows it owns. The record is
// removed only once the key is gone, so a failed delete can be retried.
func platformDelete(dir string) error {
	rec, err := readRecord(dir)
	if errors.Is(err, ErrNoKey) {
		return nil
	}
	if err != nil {
		return err
	}
	prov, err := openProvider(rec.Provider)
	if err != nil {
		return err
	}
	defer freeObject(prov)
	key, err := openKey(prov, rec.KeyName)
	switch {
	case errors.Is(err, cngError(nteBadKeyset)):
		// Already gone.
	case err != nil:
		return fmt.Errorf("open the device key in %s: %w", rec.Provider, err)
	default:
		// NCryptDeleteKey frees the handle on success.
		if err := call(procDeleteKey, key, 0); err != nil {
			freeObject(key)
			return fmt.Errorf("delete the device key from %s: %w", rec.Provider, err)
		}
	}
	if err := os.Remove(filepath.Join(dir, cngRecordName)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func platformEnforced(Device) string { return "" }
