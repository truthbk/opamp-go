# X509 Signing Extension for OpAMP

## Status: Development

This document specifies an extension to the OpAMP protocol that enables cryptographic signing and verification of remote configurations and package binary artifacts using X.509 certificates and ECDSA signatures.

## Motivation

The existing `DownloadableFile.Signature` field in the OpAMP protocol accepts an arbitrary byte payload described as "Agent specific", with GPG noted as one possible format. This ambiguity makes it impossible to build interoperable implementations: a server written in one language cannot reliably sign packages that an agent written in another language can verify.

This extension formalises signing semantics using the widely-supported X.509 PKI standard, enabling:

1. **Interoperability** — Any conformant implementation can verify signatures produced by any conformant signer.
2. **Config signing** — Remote configurations can now be signed, not just package files.
3. **Auditability** — X.509 certificates carry issuer identity, validity periods, and key usage constraints.
4. **No new dependencies** — ECDSA P-256 and X.509 certificate handling are part of the Go standard library (`crypto/ecdsa`, `crypto/x509`).

## Scope

This document covers:
- New capability bits for agents and servers
- Signing algorithm and wire format
- Certificate chain requirements
- Negotiation semantics and failure handling
- Out-of-scope items (v1)

## Capability Bits

Four new capability bits extend the existing enumerations.

### Agent Capabilities

| Constant | Value | Meaning |
|---|---|---|
| `AgentCapabilities_VerifiesRemoteConfigSignature` | `65536` (bit 16) | Agent requires the server to sign remote configs. If set, unsigned configs are **hard rejected**. |
| `AgentCapabilities_VerifiesPackageSignatures` | `131072` (bit 17) | Agent requires the server to sign package files. If set, unsigned packages are **hard rejected**. |

### Server Capabilities

| Constant | Value | Meaning |
|---|---|---|
| `ServerCapabilities_SignsRemoteConfig` | `128` (bit 7) | Server signs remote configs using X.509/ECDSA. |
| `ServerCapabilities_SignsPackages` | `256` (bit 8) | Server signs package download files using X.509/ECDSA. |

## Signing Algorithm

- **Key type**: ECDSA P-256 (prime256v1 / secp256r1)
- **Hash**: SHA-256
- **Signature format**: DER-encoded ECDSA signature (`(r, s)` as per RFC 5480)
- **Certificate chain format**: PEM bundle (leaf certificate first, followed by intermediate certificates in order toward the root; root CA not required in bundle)

These choices rely entirely on Go's standard library. No third-party dependencies are introduced.

## Protocol Fields

### `AgentRemoteConfig` (new fields)

```protobuf
message AgentRemoteConfig {
    AgentConfigMap config = 1;
    bytes config_hash = 2;

    // DER-encoded ECDSA P-256 signature over SHA-256 of the canonical
    // (deterministic) proto serialisation of the `config` field concatenated
    // with `config_hash`.
    // Present when ServerCapabilities_SignsRemoteConfig is set.
    // Status: [Development]
    bytes signature = 3;

    // PEM bundle containing the signing certificate chain.
    // Leaf certificate first, then intermediates.
    // Present when `signature` is present.
    // Status: [Development]
    bytes signing_cert_chain = 4;
}
```

### `DownloadableFile` (new field, formalised existing field)

```protobuf
message DownloadableFile {
    string download_url = 1;
    bytes content_hash = 2;

    // Formalised: DER-encoded ECDSA P-256 signature over SHA-256 of the
    // raw file content bytes (as downloaded from download_url).
    // When ServerCapabilities_SignsPackages is set, this field MUST be present.
    // Agents with AgentCapabilities_VerifiesPackageSignatures MUST verify this
    // field before installing the package.
    // Status: [Development]
    bytes signature = 3;

    Headers headers = 4;

    // PEM bundle containing the signing certificate chain.
    // Leaf certificate first, then intermediates.
    // Present when `signature` is present.
    // Status: [Development]
    bytes signing_cert_chain = 5;
}
```

## Signed Payload Definition

### Remote Config

The bytes that are signed for a remote config are:

```
signed_bytes = deterministic_proto_marshal(config) || config_hash
```

Where:
- `deterministic_proto_marshal` produces a stable byte representation of the `AgentConfigMap` proto message (e.g. using `proto.MarshalOptions{Deterministic: true}`)
- `||` denotes concatenation
- `config_hash` is the raw bytes of the `config_hash` field

The verifier computes `SHA-256(signed_bytes)` and verifies the ECDSA signature against that digest.

### Package File

The bytes that are signed for a package file are the raw content bytes of the file as downloaded from `download_url`. The verifier computes `SHA-256(file_content)` and verifies the ECDSA signature against that digest.

## Certificate Chain Requirements

The signing certificate (leaf) must satisfy:
1. **Extended Key Usage (EKU)**: Must include `ExtKeyUsageCodeSigning` (`id-kp-codeSigning`, OID 1.3.6.1.5.5.7.3.3`).
2. **Validity**: `NotBefore ≤ time_of_receipt ≤ NotAfter`.
3. **Chain of trust**: Must chain to a CA certificate present in the agent's configured trust anchor pool.
4. **Key type**: Must be an ECDSA key on P-256 (enforcement ensures algorithm agility is not accidentally bypassed).

These checks are performed by the agent's `SignatureVerifier` implementation before any config or package content is applied.

## Trust Anchor Configuration

Agents configure their signing trust anchors at startup via `StartSettings.SigningTrustAnchors`, which is an `*x509.CertPool`. If this pool is nil and a verification capability is declared, the client MUST fail to start with a clear error (`ErrSignatureVerifierRequired`).

Servers distribute their signing certificate chain inline in each signed payload (`AgentRemoteConfig.signing_cert_chain` and `DownloadableFile.signing_cert_chain`). This eliminates the need for a separate certificate exchange round-trip.

## Negotiation Semantics

The table below defines the expected behaviour for each combination of server and agent signing capabilities.

| Server has `SignsRemoteConfig` | Agent has `VerifiesRemoteConfigSignature` | Behaviour |
|---|---|---|
| No | No | Plain `RemoteConfig` sent and applied as before. No change. |
| Yes | No | Server signs but agent ignores `signature`/`signing_cert_chain` fields. Config applied normally. |
| No | Yes | Server does not populate `signature`. Agent detects missing signature, sets `RemoteConfigStatus = FAILED` with error `"server did not sign remote config"`. Config NOT applied. |
| Yes | Yes | Server signs. Agent verifies. On success: config applied. On failure: `RemoteConfigStatus = FAILED` with verification error. Config NOT applied. |

The same matrix applies to packages with `SignsPackages` / `VerifiesPackageSignatures` and `PackageStatus = InstallFailed`.

## Hard Reject Policy

An agent that declares `AgentCapabilities_VerifiesRemoteConfigSignature` or `AgentCapabilities_VerifiesPackageSignatures` MUST reject any configuration or package that does not have a valid signature. Rejection means:

- **Remote config**: The agent sets `RemoteConfigStatus.Status = FAILED` and `RemoteConfigStatus.ErrorMessage` to a human-readable description of the failure. The `RemoteConfigStatus.LastRemoteConfigHash` is NOT updated (so the server knows the config was not applied). The agent's `OnMessage` callback is NOT invoked with the rejected config.
- **Package**: The agent sets `PackageStatus.Status = InstallFailed` and `PackageStatus.ErrorMessage` to a human-readable description of the failure. The package content is NOT written to local storage.

## Go Implementation

The Go SDK provides a ready-to-use implementation in the `signing` package:

```go
import "github.com/open-telemetry/opamp-go/signing"

// Server side: generate a CA and leaf cert, create a signer
caKey, caCert, caCertPEM, _ := signing.GenerateECDSACA()
leafTLSCert, leafChainPEM, _ := signing.GenerateECDSALeafCert(caCert, caKey)
configSigner := signing.NewConfigSigner(leafTLSCert, leafChainPEM)

// Sign a config before sending
_ = configSigner.SignConfig(remoteConfig) // mutates Signature + SigningCertChain in-place

// Agent side: create a trust pool and verifier
caPool := x509.NewCertPool()
caPool.AppendCertsFromPEM(caCertPEM)
verifier := signing.NewX509SignatureVerifier(caPool)

// Pass verifier to client start settings
settings := types.StartSettings{
    SignatureVerifier: verifier,
    // ...
}
// Also set capabilities:
client.SetCapabilities(
    protobufs.AgentCapabilities_AgentCapabilities_VerifiesRemoteConfigSignature |
    protobufs.AgentCapabilities_AgentCapabilities_ReportsStatus,
)
```

The client will automatically verify incoming configs and packages and hard-reject them on failure.

## Out of Scope (v1)

The following items are intentionally excluded from this version:

- **Certificate Revocation Lists (CRL)** and **OCSP stapling**: Revocation checking is not performed. Operators should use short-lived certificates (e.g. validity ≤ 24 hours) to limit the window of exposure for a compromised signing key.
- **RSA signing**: Only ECDSA P-256 is supported. RSA may be added in a future version.
- **Trust-On-First-Use (TOFU)**: The trust anchor pool must be pre-configured. Dynamic trust establishment is not supported.
- **Signature algorithm negotiation**: The algorithm is fixed at ECDSA P-256 + SHA-256.
- **Multiple signers**: Each payload is signed by exactly one key.
