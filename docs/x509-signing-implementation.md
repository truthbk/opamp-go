# X509 Signing Extension — Implementation Reference

This document describes the design rationale, implementation details, and test coverage
for the X.509 signing extension added to the opamp-go SDK.

---

## Table of Contents

1. [Problem Statement](#problem-statement)
2. [Design Goals and Decisions](#design-goals-and-decisions)
3. [Protocol Changes](#protocol-changes)
4. [Architecture Overview](#architecture-overview)
5. [Implementation: `signing/` Package](#implementation-signing-package)
6. [Implementation: Client Wiring](#implementation-client-wiring)
7. [Test Suite](#test-suite)
8. [Backwards Compatibility](#backwards-compatibility)
9. [File Index](#file-index)

---

## Problem Statement

The OpAMP protocol already carried a `DownloadableFile.Signature` field described as
"Agent specific (e.g. GPG detached signature)". This vagueness had three practical
problems:

1. **No interoperability.** A server written in Python cannot produce a signature that
   a Go agent can verify without coordination outside the protocol.
2. **Config payloads were unsigned.** `AgentRemoteConfig` had no signature field at
   all. An attacker who could man-in-the-middle the OpAMP connection could inject
   arbitrary configuration without detection.
3. **The `Signature` field was pass-through only.** The SDK delivered it to the agent
   implementation via `PackagesStateProvider.UpdateContent()` but never verified it
   itself. Verification was entirely optional and undocumented.

The extension replaces the vague per-agent contract with a concrete, interoperable
X.509/ECDSA scheme and adds SDK-level enforcement when the agent declares the
corresponding capability.

---

## Design Goals and Decisions

### Optionality first

Neither server nor agent is required to sign. The feature is gated by new capability
bits. Old agents connecting to a new server, or new agents connecting to an old server,
both continue to work without modification.

### Hard rejection over silent acceptance

When an agent declares `VerifiesRemoteConfigSignature` or `VerifiesPackageSignatures`,
an unsigned payload or a payload with an invalid signature is **rejected**. The SDK
does not call `OnMessage` with the config, and does not call
`PackagesStateProvider.UpdateContent` for the file. The server is informed via
`RemoteConfigStatus = FAILED` or `PackageStatus = InstallFailed` with a descriptive
error message.

Soft acceptance (warn-and-apply) was explicitly rejected. An agent that declares it
requires signatures must be able to trust that it never applies an unsigned payload.

### Algorithm: ECDSA P-256 + SHA-256

- **Standard library only.** No new dependencies are introduced. `crypto/ecdsa`,
  `crypto/x509`, `encoding/binary` are all part of the Go standard library.
  Signing and verification use `ecdsa.SignASN1` / `ecdsa.VerifyASN1` (available since
  Go 1.15), which produce and consume standards-compliant DER-encoded signatures without
  manual ASN.1 marshalling.
- **Small keys, fast verification.** A P-256 key is ≈3× smaller than RSA-4096 and
  verification is significantly faster on the hot path.
- **Widely supported.** P-256 is the most common ECDSA curve and is hardware-accelerated
  on most modern platforms.
- **SHA-256 minimum.** Matches the spec's code-signing recommendations.

### Inline certificate chain distribution

The signing certificate chain is embedded directly in each signed payload
(`AgentRemoteConfig.signing_cert_chain`, `DownloadableFile.signing_cert_chain`).
This eliminates an extra round-trip to fetch the server's public key and makes each
signed artifact self-contained. Agents configure their trust anchors once at startup
via `StartSettings.SignatureVerifier`.

### No `.proto` source changes in this repository

The `.proto` source is maintained in the upstream
[opamp-spec](https://github.com/open-telemetry/opamp-spec) repository; this repository
carries only the compiled `opamp.pb.go`. New fields and capability constants were
therefore added manually to `protobufs/opamp.pb.go` following the exact conventions of
the generated code. `docs/x509-signing-proto-proposal.md` contains the exact diffs to
propose upstream.

### Temp-file streaming for package verification

Package files are streamed to a temporary file during download (using `io.TeeReader`
into `os.CreateTemp`), so the progress reporter continues to work. The signature is
verified over the full byte content of the temp file before handing it to
`PackagesStateProvider.UpdateContent`. If verification fails, the temp file is deleted
and `InstallFailed` is reported. This avoids buffering arbitrarily large binaries in
heap memory while still allowing byte-accurate signature verification.

### Resource limits on server-supplied data

Three size limits protect the agent from a malicious or buggy server:

- **Package downloads** (`packagessyncer.go`): capped at `maxPackageBodyBytes` (512 MiB)
  via `io.LimitReader`. Downloads that exceed the limit are rejected before the content
  reaches the signature verifier.
- **HTTP control-plane responses** (`httpsender.go`): `receiveResponse` caps the HTTP
  response body at `maxControlPlaneBodyBytes` (16 MiB) via `io.LimitReader`. This
  prevents a malicious server from exhausting agent heap memory by sending oversized
  `ServerToAgent` protobuf messages containing large `Signature` or `SigningCertChain`
  fields.
- **WebSocket control-plane frames** (`wsreceiver.go`): `NewWSReceiver` calls
  `conn.SetReadLimit(maxControlPlaneBodyBytes)` so the same 16 MiB ceiling applies to
  the WebSocket transport. Both transports now enforce identical limits, preventing an
  attacker from bypassing the HTTP guard by using the WebSocket endpoint.

---

## Protocol Changes

### New fields

**`AgentRemoteConfig`** (proto field numbers 3 and 4, previously unused):

```go
// DER-encoded ECDSA P-256 signature over SHA-256 of:
//   4-byte big-endian len(marshal(config)) || marshal(config) || config_hash
Signature        []byte  `protobuf:"bytes,3,..."`
SigningCertChain []byte  `protobuf:"bytes,4,..."`  // PEM bundle, leaf first
```

**`DownloadableFile`** (proto field number 5, previously unused):

```go
// PEM bundle for the signing cert chain that produced Signature (field 3).
SigningCertChain []byte  `protobuf:"bytes,5,..."`
```

The existing `DownloadableFile.Signature` field (field 3) is formalised: it now carries
a DER-encoded ECDSA P-256 signature over SHA-256 of the raw file content.

### New capability constants

| Constant | Value | Side | Meaning |
|---|---|---|---|
| `AgentCapabilities_VerifiesRemoteConfigSignature` | `65536` (bit 16) | Agent | Agent hard-rejects unsigned or invalid-sig remote configs |
| `AgentCapabilities_VerifiesPackageSignatures` | `131072` (bit 17) | Agent | Agent hard-rejects unsigned or invalid-sig package files |
| `ServerCapabilities_SignsRemoteConfig` | `128` (bit 7) | Server | Server signs remote configs |
| `ServerCapabilities_SignsPackages` | `256` (bit 8) | Server | Server signs package files |

The next available bit for `AgentCapabilities` was bit 16 (32768 × 2 = 65536).
The next available bit for `ServerCapabilities` was bit 7 (64 × 2 = 128).

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│  Server application                                      │
│                                                          │
│  signing.GenerateECDSACA()          ─► CA key + cert    │
│  signing.GenerateECDSALeafCert()    ─► leaf key + chain │
│  signing.NewConfigSigner(leaf, chain)                    │
│     └─ signer.SignConfig(config)  ─► config.Signature   │
│                                       config.SignChain   │
│  signing.NewFileSigner(leaf, chain)                      │
│     └─ signer.SignFile(file, content) ─► file.Signature │
│                                          file.SignChain  │
└─────────────────┬───────────────────────────────────────┘
                  │ OpAMP protocol (ServerToAgent)
                  ▼
┌─────────────────────────────────────────────────────────┐
│  opamp-go client SDK                                     │
│                                                          │
│  StartSettings.SignatureVerifier = X509SignatureVerifier │
│                                                          │
│  receivedprocessor.ProcessReceivedMessage()              │
│     └─ if VerifiesRemoteConfigSignature capability:      │
│           verifier.VerifyRemoteConfig(config)            │
│             ├─ OK  → deliver to OnMessage callback       │
│             └─ Fail → RemoteConfigStatus = FAILED        │
│                       (OnMessage not called)             │
│                                                          │
│  packagesSyncer.downloadFile()                           │
│     └─ if VerifiesPackageSignatures capability:          │
│           stream to temp file                            │
│           verifier.VerifyFile(file, content)             │
│             ├─ OK  → UpdateContent(tempFile, ...)        │
│             └─ Fail → delete temp file                   │
│                       PackageStatus = InstallFailed      │
└─────────────────────────────────────────────────────────┘
```

---

## Implementation: `signing/` Package

The `signing/` package is standalone — it depends only on the `protobufs` package and
the Go standard library. It can be imported by server applications, agent
implementations, and the SDK's client internals without creating import cycles.

### `signing/certs.go` — Key and certificate generation

```go
func GenerateECDSACA() (*ecdsa.PrivateKey, *x509.Certificate, []byte, error)
func GenerateECDSALeafCert(ca *x509.Certificate, caKey *ecdsa.PrivateKey) (*tls.Certificate, []byte, error)
```

`GenerateECDSACA` produces a self-signed CA certificate valid for 24 hours (suitable for
development and testing). `GenerateECDSALeafCert` produces a leaf certificate signed by
the CA with `ExtKeyUsageCodeSigning` set — the EKU that the verifier requires. Both
functions return PEM-encoded bytes for serialisation.

The leaf cert's private key is returned embedded inside a `*tls.Certificate` (the same
type used throughout the Go TLS stack), making it directly usable with `NewConfigSigner`
and `NewFileSigner`.

### `signing/verifier.go` — Signature verification

#### `SignatureVerifier` interface

```go
type SignatureVerifier interface {
    VerifyRemoteConfig(config *protobufs.AgentRemoteConfig) error
    VerifyFile(file *protobufs.DownloadableFile, content []byte) error
}
```

The interface exists for three reasons:
1. **Testability.** The client's `receivedprocessor` and `packagesSyncer` accept an
   interface, not a concrete type, so tests can inject mock verifiers.
2. **Pluggability.** Operators who need hardware-backed signing (HSM, KMS) can implement
   their own verifier without forking the SDK.
3. **Future algorithm agility.** A different signing algorithm can be introduced as a
   new `SignatureVerifier` implementation without changing the client internals.

#### `X509SignatureVerifier`

`NewX509SignatureVerifier(trustAnchors)` panics if `trustAnchors` is nil. This is
intentional: passing nil would cause `x509.Certificate.Verify` to fall back to the
platform system root pool, silently trusting the entire public web PKI rather than the
operator-configured CA. The panic fires at the misconfigured call site rather than
allowing a silent trust-boundary bypass.

The concrete implementation performs:

1. **Presence check.** If `Signature` or `SigningCertChain` is absent, returns
   `ErrMissingSignature`. This is the sentinel error that lets callers distinguish
   "no signature" (hard-reject) from "bad signature" (verification failure).

2. **Certificate chain parse.** Reads all `CERTIFICATE` PEM blocks from the chain
   bundle. The first block is the leaf; remaining blocks are intermediates. Bundles
   with more than `maxCertChainLen` (10) certificates are rejected before any ASN.1
   parsing occurs, preventing CPU/memory exhaustion from server-supplied oversized chains.

3. **Chain verification.** Calls `leaf.Verify(x509.VerifyOptions{...})` with:
   - `Roots`: the agent's pre-configured trust anchors.
   - `Intermediates`: any intermediate certs from the bundle.
   - `KeyUsages`: `ExtKeyUsageCodeSigning` — the verifier rejects certs that are not
     explicitly authorised for code signing, even if they chain to a trusted CA.
   - `CurrentTime`: `time.Now()` — expired certs are rejected.

4. **Digest computation.** For remote configs: `SHA-256(4-byte-len || marshal(config.Config) || config.ConfigHash)`.
   For files: `SHA-256(raw_file_content)`.

5. **ECDSA verification.** Calls `ecdsa.VerifyASN1(ecKey, digest, sig)` with the leaf
   cert's public key. Returns an error if the key type is not `*ecdsa.PublicKey` or if
   the signature does not match. `ecdsa.VerifyASN1` correctly rejects signatures with
   trailing bytes (the older `asn1.Unmarshal` path silently dropped them).

#### Signed payload for remote configs

The signed bytes have the following format:

```
[ 4 bytes big-endian: len(configBytes) ][ configBytes ][ config.ConfigHash ]
```

- **`configBytes`** — deterministic proto marshal of `config.Config` (the `AgentConfigMap`).
  Deterministic marshalling is required so the same proto message always produces the
  same bytes regardless of field insertion order.
- **`config.ConfigHash`** — the raw hash bytes the server already includes for change
  detection. Including the hash binds the signature to a specific config version,
  preventing replay of an old signature with a new hash.
- **4-byte length prefix** — a big-endian `uint32` length of `configBytes` prefixed
  before the config bytes. This unambiguously delimits the two fields and prevents a
  length-confusion attack where distinct `(Config, Hash)` pairs could otherwise produce
  identical byte strings. `configSignedPayload` guards against `uint32` overflow
  (`len(configBytes) > math.MaxUint32`) and returns an error rather than silently
  truncating the prefix.

### `signing/signer.go` — Signature creation (server side)

```go
type ConfigSigner struct { ... }
func NewConfigSigner(leafCert *tls.Certificate, certChainPEM []byte) (*ConfigSigner, error)
func (s *ConfigSigner) SignConfig(config *protobufs.AgentRemoteConfig) error

type FileSigner struct { ... }
func NewFileSigner(leafCert *tls.Certificate, certChainPEM []byte) (*FileSigner, error)
func (s *FileSigner) SignFile(file *protobufs.DownloadableFile, content []byte) error
```

Both signers:
- Extract the `*ecdsa.PrivateKey` from the `tls.Certificate` at construction time,
  returning an error if the cert's key is not ECDSA (enforcement over silent failure).
- On `SignConfig`/`SignFile`, compute the same digest as the verifier, call
  `ecdsa.SignASN1(rand.Reader, key, digest)` to produce a DER-encoded signature, and
  mutate the proto message's `Signature` and `SigningCertChain` fields in place.
  `ecdsa.SignASN1` is used in preference to the older `ecdsa.Sign` + `asn1.Marshal`
  path to keep the signing and verification APIs symmetric and avoid manual ASN.1 work.
- The `certChainPEM` stored at construction is copied verbatim into
  `SigningCertChain` — the server is responsible for providing the correct chain.

---

## Implementation: Client Wiring

### `client/types/startsettings.go`

```go
SignatureVerifier signing.SignatureVerifier
```

A single new field on `StartSettings`. The field is intentionally an interface type so
the import of the `signing` package does not force server implementations (which import
`client/types` indirectly) to depend on the signing logic.

If the field is nil and either verification capability is declared, `PrepareStart`
returns `ErrSignatureVerifierRequired` before the connection is established.

### `client/internal/clientcommon.go`

**`ErrSignatureVerifierRequired`** — a new sentinel error exported from the `internal`
package, surfaced by `PrepareStart` to give a clear message when configuration is
inconsistent.

**`ClientCommon.SignatureVerifier`** — the verifier is stored on the shared state
struct so it can be threaded to both the received-message processor and the package
syncer without passing it through multiple constructor chains.

**`validateCapabilities` addition:**

```go
needsVerifier := capabilities & AgentCapabilities_VerifiesRemoteConfigSignature != 0 ||
                 capabilities & AgentCapabilities_VerifiesPackageSignatures != 0
if needsVerifier && c.SignatureVerifier == nil {
    return ErrSignatureVerifierRequired
}
```

This check runs alongside the existing capability consistency checks (e.g.,
`PackagesStateProvider` must be set when `AcceptsPackages` is declared).

### `client/internal/receivedprocessor.go`

The `receivedProcessor` struct gains a `signatureVerifier signing.SignatureVerifier`
field, set via the updated `newReceivedProcessor` constructor.

The remote config handling block is extended:

```go
if msg.RemoteConfig != nil {
    if r.hasCapability(AcceptsRemoteConfig) {
        if r.hasCapability(VerifiesRemoteConfigSignature) {
            if err := r.verifyRemoteConfigSignature(ctx, msg.RemoteConfig); err != nil {
                r.logger.Errorf(ctx, "Remote config signature verification failed: %v", err)
                // Hard reject: msgData.RemoteConfig is NOT set.
            } else {
                msgData.RemoteConfig = msg.RemoteConfig
            }
        } else {
            msgData.RemoteConfig = msg.RemoteConfig  // unchanged path
        }
    }
}
```

`verifyRemoteConfigSignature` is a private method that:
1. Returns `ErrMissingSignature` (via the verifier) if the server did not sign.
2. Returns the ECDSA verification error if the signature is invalid.
3. On any error: persists `RemoteConfigStatus = FAILED` with `LastRemoteConfigHash` set
   to **the rejected message's own `ConfigHash`** (not the previously applied hash),
   enqueues the status update via `sender.NextMessage().Update(...)`, and calls
   `sender.ScheduleSend()`. Using the rejected config's hash is required so the server
   knows which version was rejected and does not re-send it in an infinite loop.
4. Does NOT call `OnMessage` with the rejected config.

The `PackagesSyncer` call is updated to pass the verifier through:

```go
pkgSyncer, err := NewPackagesSyncer(..., r.signatureVerifier)
```

### `client/internal/packagessyncer.go`

`NewPackagesSyncer` gains a `signatureVerifier signing.SignatureVerifier` parameter.

The `downloadFile` method is restructured:

```
Old flow:
  resp.Body → io.TeeReader (progress) → UpdateContent

New flow:
  io.LimitReader(resp.Body, 512 MiB + 1)    ← rejects oversized downloads
    → io.TeeReader (progress)
    → os.CreateTemp (temp file)
  if written > 512 MiB: return error
  if VerifiesPackageSignatures capability set:
      if signatureVerifier == nil: return hard error   ← programming error, never silent skip
      content = os.ReadFile(tmpPath)
      err = signatureVerifier.VerifyFile(file, content)
      if err: delete tmpPath, return wrapped error
  open tmpPath for reading
  UpdateContent(ctx, pkgName, tmpFileReader, contentHash, legacySignature)
  defer os.Remove(tmpPath)
```

The `maxPackageBodyBytes` constant (512 MiB) caps the download body. Reading one byte
beyond the limit is used to detect overflow: if `io.Copy` writes more than
`maxPackageBodyBytes` bytes, `downloadFile` returns an error and the temp file is
discarded.

The signature verification guard is keyed solely on the capability bit. If
`signatureVerifier` is nil while `VerifiesPackageSignatures` is set — a state that
`validateCapabilities` prevents at `Start()` time — `downloadFile` returns a hard error
(`"SignatureVerifier is not configured"`) rather than silently skipping verification.
This ensures there is no latent path by which a programming error could bypass the
security check.

The legacy `file.Signature` bytes continue to be passed to `UpdateContent` unchanged,
preserving the existing interface contract for agent implementations that perform their
own secondary verification.

### Transport-layer threading and limits

Both transport implementations pass the verifier through the call chain and enforce
body size limits on received data:

| Call site | Change |
|---|---|
| `client/internal/wsreceiver.go: NewWSReceiver` | Added `signatureVerifier` parameter; calls `conn.SetReadLimit(maxControlPlaneBodyBytes)` to cap WS frame size |
| `client/internal/httpsender.go: HTTPSender.Run` | Added `signatureVerifier signing.SignatureVerifier` parameter |
| `client/internal/httpsender.go: receiveResponse` | `io.LimitReader(resp.Body, maxControlPlaneBodyBytes+1)` guards against oversized ServerToAgent responses |
| `client/wsclient.go` | Passes `c.common.SignatureVerifier` to `NewWSReceiver` |
| `client/httpclient.go` | Passes `c.common.SignatureVerifier` to `sender.Run` |

Existing test call sites in `wsreceiver_test.go` and `httpsender_test.go` pass `nil`
for the new parameter, leaving their behaviour unchanged.

---

## Test Suite

All tests are in three locations:
- `signing/` — unit tests for the signing and verification primitives.
- `client/internal/packagessyncer_signing_test.go` — integration tests for the package
  syncer's signature enforcement.
- `client/internal/receivedprocessor_signing_test.go` — unit tests for the
  remote-config signature enforcement in `receivedprocessor`.

### `signing/verifier_test.go` — 14 tests

These tests validate every branch of the `X509SignatureVerifier` implementation.

| Test | What it validates | Rationale |
|---|---|---|
| `TestVerifyRemoteConfig_Valid` | A correctly signed config verifies without error. | Baseline correctness — the happy path must work before testing failure modes. |
| `TestVerifyRemoteConfig_TamperedSig` | Flipping one bit in the DER signature causes a verification error. | Ensures the ECDSA verification is actually performed, not bypassed. Without this test a trivially wrong implementation (`return nil`) would appear correct. |
| `TestVerifyRemoteConfig_TamperedConfig` | Changing the config body after signing causes a verification error. | Confirms the signed payload covers the config content, not just the hash. An attacker who can modify the config bytes after signing should be detected. |
| `TestVerifyRemoteConfig_ExpiredCert` | A leaf cert with `NotAfter` in the past causes a chain verification error. | X.509 certificate validity windows are the primary mechanism for bounding exposure after a key compromise. Skipping this check would make certificates permanent. |
| `TestVerifyRemoteConfig_UnknownCA` | A cert from a CA not in the trust pool is rejected. | The trust anchor pool is the entire basis of the PKI model. A bypass here would allow any cert to sign. |
| `TestVerifyRemoteConfig_WrongEKU` | A cert with `ExtKeyUsageServerAuth` but not `ExtKeyUsageCodeSigning` is rejected. | Extended Key Usage constraints limit what a certificate can be used for. Ignoring EKU would allow an attacker to repurpose a server TLS certificate for code signing. |
| `TestVerifyRemoteConfig_MissingSignature` | A config with no `Signature` field returns `ErrMissingSignature`. | Hard-reject semantics require a specific sentinel error that the SDK can detect and act on. Tests that `errors.Is` works correctly so callers can distinguish "unsigned" from "bad signature". |
| `TestVerifyRemoteConfig_OversizedCertChain` | A PEM bundle with 11 certificates returns an error containing "maximum allowed length". | Verifies the `maxCertChainLen` DoS protection boundary. Without this test a regression that removed the limit would not be detected. |
| `TestVerifyRemoteConfig_NilConfigMap` | A config with a nil `Config` field (only `ConfigHash` set) signs and verifies correctly. | Exercises the `configSignedPayload` nil-Config branch; ensures the nil case does not produce an incorrect payload or panic. |
| `TestVerifyFile_Valid` | A correctly signed file verifies without error. | Baseline correctness for the file signing path, which uses a different payload (raw bytes, not proto). |
| `TestVerifyFile_TamperedContent` | Changing file bytes after signing causes a verification error. | Confirms the signature binds to the content, not just the metadata. An attacker who substitutes a different binary after the server signs should be detected. |
| `TestVerifyFile_TamperedSig` | Corrupting the DER signature on a file causes an error. | Parallel to the config tampered-sig test; ensures both code paths have byte-level integrity checking. |
| `TestVerifyFile_MissingSignature` | A file with no `Signature`/`SigningCertChain` returns `ErrMissingSignature`. | Same rationale as the config missing-signature test, covering the separate `VerifyFile` code path. |
| `TestVerifyFile_UnknownCA` | Signing with CA-A and verifying with a CA-B pool causes `VerifyFile` to fail with "certificate chain verification failed". | Confirms `VerifyFile` threads through `verifyCertChain` — the cert-rejection path was previously covered only for `VerifyRemoteConfig`. |

#### Test infrastructure

A `generateCustomLeafCert` helper in the test file allows creating leaf certificates
with arbitrary `NotBefore`/`NotAfter` values and EKU sets. This is needed for the
expiry and wrong-EKU tests without exposing those parameters on the production API
(production certs should always be short-lived with the correct EKU).

### `signing/signer_test.go` — 3 tests

These tests validate the server-side signing helpers.

| Test | What it validates | Rationale |
|---|---|---|
| `TestConfigSigner_RoundTrip` | Sign then verify with the same CA — end-to-end sign-verify cycle. | Confirms that the signer and verifier agree on the canonical payload format. If either side diverges in how it constructs the bytes to sign, a round-trip test will catch it. |
| `TestFileSigner_RoundTrip` | Sign a file then verify the content — end-to-end for the file path. | Separate from the config round-trip because the payload construction differs (raw bytes vs. proto marshal). |
| `TestConfigSigner_RejectsRSAKey` | Passing a `tls.Certificate` with an RSA private key to `NewConfigSigner` or `NewFileSigner` returns an error containing "ECDSA". | Directly tests the key-type enforcement path. A regression that silently accepted a non-ECDSA key would produce a panic or wrong signature at signing time. |

Note: the cross-CA rejection scenario is covered by `TestVerifyRemoteConfig_UnknownCA` and `TestVerifyFile_UnknownCA` in `verifier_test.go`; a duplicate in `signer_test.go` was removed.

### `client/internal/receivedprocessor_signing_test.go` — 7 tests

These tests exercise `verifyRemoteConfigSignature` and `validateCapabilities` through
`ProcessReceivedMessage` and `ClientCommon` directly, without a live transport.

| Test | What it validates | Rationale |
|---|---|---|
| `TestReceivedProcessor_ValidSignatureDelivered` | Valid signature + capability → config delivered to `OnMessage`, no status update sent. | Baseline correctness for the remote-config signing path end-to-end. |
| `TestReceivedProcessor_InvalidSignatureRejected` | Invalid signature (wrong CA) → `OnMessage` not called, `RemoteConfigStatus = FAILED` sent, `LastRemoteConfigHash` equals the rejected config's hash. | Validates hard-reject semantics and the corrected hash field (using the rejected hash, not the previously applied hash, prevents a server resend loop). |
| `TestReceivedProcessor_MissingSignatureRejected` | Unsigned config + capability → hard-rejected with `FAILED` status. | Ensures agents that declare the verification capability never silently apply unsigned configs. |
| `TestReceivedProcessor_SignatureIgnoredWithoutCapability` | `VerifiesRemoteConfigSignature` not declared → config delivered regardless of signature validity. | Backwards compatibility: capability-gating must be strictly respected. |
| `TestReceivedProcessor_NilVerifierWithCapabilityFails` | `VerifiesRemoteConfigSignature` set + nil verifier → hard-rejected with `FAILED` status, not silently skipped. | Confirms the processor's own nil-verifier guard produces the correct outcome; `validateCapabilities` prevents this state at startup but the processor must not silently bypass security if somehow reached. |
| `TestClientCommon_ErrSignatureVerifierRequired/VerifiesRemoteConfigSignature` | `validateCapabilities` with `VerifiesRemoteConfigSignature` + nil verifier returns `ErrSignatureVerifierRequired`. | Tests the `PrepareStart`-time enforcement that prevents mis-configuration from reaching the network. |
| `TestClientCommon_ErrSignatureVerifierRequired/VerifiesPackageSignatures` | `validateCapabilities` with `VerifiesPackageSignatures` + nil verifier returns `ErrSignatureVerifierRequired`. | Covers the second half of the `||` in `validateCapabilities` — both signing capability bits must be individually tested. |

### `client/internal/packagessyncer_signing_test.go` — 5 tests

These are integration-level tests. They spin up an `httptest.Server`, drive the
package syncer through `doSync`, and assert the resulting `PackageStatus`. They use the
existing `InMemPackagesStore`, `MockSender`, and `createTestHTTPServer` helpers from the
package syncer test file.

| Test | What it validates | Rationale |
|---|---|---|
| `TestPackageSyncer_ValidSignatureAccepted` | Capability set + valid verifier + correctly signed file → `Installed`. | Confirms the happy path through the full download-then-verify-then-install sequence. This is the most important test: it ensures the feature works end-to-end under realistic conditions (HTTP server, progress reporter, temp file). |
| `TestPackageSyncer_InvalidSignatureRejected` | Capability set + wrong-CA verifier + signed file → `InstallFailed` with "signature verification failed" in the error message. | Validates that a man-in-the-middle who intercepts the download URL or rotates the file content is detected. Uses a separate CA (not the one that signed) to simulate an unknown signer. |
| `TestPackageSyncer_MissingSignatureRejected` | Capability set + verifier + no signature on file → `InstallFailed`. | Hard-reject semantics: an agent that requires signatures must never install an unsigned package, even from a server that simply forgot to sign. |
| `TestPackageSyncer_SignatureIgnoredWithoutCapability` | No `VerifiesPackageSignatures` capability, wrong-CA verifier, signed file → `Installed`. | Backwards compatibility: an agent that does not declare the capability must not be affected by the presence of signing infrastructure. Old agents connecting to a signing-enabled server must work identically to before. |
| `TestPackageSyncer_NilVerifierWithCapabilityFails` | Capability set but `signatureVerifier == nil` → `InstallFailed` with "SignatureVerifier is not configured". | Verifies the hard-error behavior of the syncer's nil-verifier guard. The capability bit alone is sufficient to require verification; a nil verifier must never silently skip it. |

---

## Backwards Compatibility

The extension is designed so that **no existing code path changes** unless the new
capability bits are explicitly set.

| Agent caps | Server caps | Behaviour |
|---|---|---|
| Neither new bit set | Neither new bit set | Identical to pre-extension. `Signature`/`SigningCertChain` fields are ignored. |
| Neither new bit set | `SignsRemoteConfig` or `SignsPackages` | Server populates new fields; agent ignores them. Identical to before. |
| `VerifiesRemoteConfigSignature` or `VerifiesPackageSignatures` set | Neither new bit set | Agent expects signatures, server does not provide them → hard reject. Agent must not set these bits unless it knows the server signs. |
| Both sets | Both sets | Full signing and verification. |

All existing `NewWSReceiver`, `HTTPSender.Run`, and `NewPackagesSyncer` call sites in
tests were updated to pass `nil` for the new `signatureVerifier` parameter, leaving
their test behaviour entirely unchanged.

---

## File Index

| File | Type | Purpose |
|---|---|---|
| `docs/x509-signing.md` | Spec | End-user specification for the extension |
| `docs/x509-signing-proto-proposal.md` | Spec | Upstream `opamp-spec` PR proposal |
| `docs/x509-signing-implementation.md` | This file | Implementation reference |
| `protobufs/opamp.pb.go` | Modified | New fields on `AgentRemoteConfig` and `DownloadableFile`; new capability constants |
| `signing/certs.go` | New | ECDSA P-256 CA and leaf cert generation helpers |
| `signing/verifier.go` | New | `SignatureVerifier` interface + `X509SignatureVerifier` implementation |
| `signing/signer.go` | New | `ConfigSigner` and `FileSigner` for server-side use |
| `signing/verifier_test.go` | New | 14 unit tests for `X509SignatureVerifier` (including `maxCertChainLen`, nil-Config, and `VerifyFile` cert-chain coverage) |
| `signing/signer_test.go` | New | 3 unit tests for `ConfigSigner` and `FileSigner` (duplicate cross-CA test removed) |
| `client/types/startsettings.go` | Modified | Added `SignatureVerifier signing.SignatureVerifier` field |
| `client/internal/clientcommon.go` | Modified | `ErrSignatureVerifierRequired`, `SignatureVerifier` field, `validateCapabilities` guard, `PrepareStart` wiring |
| `client/internal/receivedprocessor.go` | Modified | `signatureVerifier` field, `verifyRemoteConfigSignature` method, hard-reject logic in `ProcessReceivedMessage` |
| `client/internal/packagessyncer.go` | Modified | `signatureVerifier` field, temp-file streaming, signature verify before `UpdateContent` |
| `client/internal/wsreceiver.go` | Modified | `signatureVerifier` parameter threaded through `NewWSReceiver` |
| `client/internal/httpsender.go` | Modified | `signatureVerifier` parameter threaded through `HTTPSender.Run` |
| `client/wsclient.go` | Modified | Passes `c.common.SignatureVerifier` to `NewWSReceiver` |
| `client/httpclient.go` | Modified | Passes `c.common.SignatureVerifier` to `sender.Run` |
| `client/internal/packagessyncer_signing_test.go` | New | 5 integration tests for signing enforcement in the package syncer |
| `client/internal/receivedprocessor_signing_test.go` | New | 7 unit tests for remote-config signing enforcement in `receivedprocessor` |
| `client/internal/packagessyncer_test.go` | Modified | Updated `NewPackagesSyncer` call sites with `nil` verifier |
| `client/internal/wsreceiver_test.go` | Modified | Updated `NewWSReceiver` call sites with `nil` verifier |
| `client/internal/httpsender_test.go` | Modified | Updated `newReceivedProcessor` call sites with `nil` verifier; added `TestHTTPSenderResponseBodySizeLimit` |
