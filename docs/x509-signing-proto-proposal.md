# X509 Signing — Upstream Proto Proposal

This document contains the exact proto changes to propose to the
[opamp-spec](https://github.com/open-telemetry/opamp-spec) repository.

## Background

See [x509-signing.md](x509-signing.md) for the full specification rationale and semantics.

## Diff Against `opamp.proto`

### 1. `AgentRemoteConfig` — two new fields

```diff
 message AgentRemoteConfig {
   // Agent config offered by the management Server to the Agent instance.
   AgentConfigMap config = 1;

   // Hash of "config". ...
   bytes config_hash = 2;
+
+  // Optional DER-encoded ECDSA P-256 signature over SHA-256 of the
+  // deterministic proto serialisation of `config` concatenated with
+  // `config_hash`.
+  // Present when the Server has the SignsRemoteConfig capability.
+  // Agents with the VerifiesRemoteConfigSignature capability MUST verify
+  // this field and MUST reject the config if verification fails.
+  // Status: [Development]
+  bytes signature = 3;
+
+  // PEM bundle of the signing certificate chain used to produce `signature`.
+  // Leaf certificate first, then intermediates (root not required).
+  // Present when `signature` is present.
+  // Status: [Development]
+  bytes signing_cert_chain = 4;
 }
```

### 2. `DownloadableFile` — one new field, formalised existing field

```diff
 message DownloadableFile {
   // The URL from which the file can be downloaded using HTTP GET request.
   string download_url = 1;

   // The hash of the file content.
   bytes content_hash = 2;

-  // Optional signature of the file content. Can be used by the Agent to verify
-  // the authenticity of the downloaded file, for example can be the
-  // detached GPG signature. The exact signing and verification method is
-  // Agent specific.
+  // Optional DER-encoded ECDSA P-256 signature over SHA-256 of the raw
+  // downloaded file content bytes.
+  // When the Server has the SignsPackages capability, this field MUST be
+  // present. Agents with the VerifiesPackageSignatures capability MUST
+  // verify this field before installing the package and MUST set
+  // PackageStatus.status = InstallFailed if verification fails.
+  // Status: [Development]
   bytes signature = 3;

   // Optional headers to use when downloading a file.
   Headers headers = 4;
+
+  // PEM bundle of the signing certificate chain used to produce `signature`.
+  // Leaf certificate first, then intermediates (root not required).
+  // Present when `signature` is present.
+  // Status: [Development]
+  bytes signing_cert_chain = 5;
 }
```

### 3. `AgentCapabilities` — two new enum values

```diff
 enum AgentCapabilities {
   AgentCapabilities_Unspecified = 0;
   AgentCapabilities_ReportsStatus = 1;
   // ... existing values ...
   AgentCapabilities_ReportsConnectionSettingsStatus = 32768;
+
+  // The Agent will verify X.509 signatures on received RemoteConfigs.
+  // If set, unsigned configs are hard-rejected: the Agent sets
+  // RemoteConfigStatus.status = FAILED and does not apply the config.
+  // Status: [Development]
+  AgentCapabilities_VerifiesRemoteConfigSignature = 65536;
+
+  // The Agent will verify X.509 signatures on received package files.
+  // If set, unsigned packages are hard-rejected: the Agent sets
+  // PackageStatus.status = InstallFailed and does not install the package.
+  // Status: [Development]
+  AgentCapabilities_VerifiesPackageSignatures = 131072;
 }
```

### 4. `ServerCapabilities` — two new enum values

```diff
 enum ServerCapabilities {
   ServerCapabilities_Unspecified = 0;
   ServerCapabilities_AcceptsStatus = 1;
   // ... existing values ...
   ServerCapabilities_AcceptsConnectionSettingsRequest = 64;
+
+  // The Server signs remote configurations using ECDSA P-256 + SHA-256.
+  // The signature is placed in AgentRemoteConfig.signature and the
+  // signing certificate chain in AgentRemoteConfig.signing_cert_chain.
+  // Status: [Development]
+  ServerCapabilities_SignsRemoteConfig = 128;
+
+  // The Server signs downloadable package files using ECDSA P-256 + SHA-256.
+  // The signature is placed in DownloadableFile.signature and the
+  // signing certificate chain in DownloadableFile.signing_cert_chain.
+  // Status: [Development]
+  ServerCapabilities_SignsPackages = 256;
 }
```

## Rationale for Field Number Choices

- `AgentRemoteConfig.signature = 3` and `.signing_cert_chain = 4`: next available after existing fields 1 and 2.
- `DownloadableFile.signing_cert_chain = 5`: next available after existing fields 1–4 (field 3 is the existing `signature` field, field 4 is `headers`).
- `AgentCapabilities_VerifiesRemoteConfigSignature = 65536` (bit 16) and `_VerifiesPackageSignatures = 131072` (bit 17): next available power-of-two values after the existing maximum of 32768 (bit 15).
- `ServerCapabilities_SignsRemoteConfig = 128` (bit 7) and `_SignsPackages = 256` (bit 8): next available power-of-two values after the existing maximum of 64 (bit 6).

## Compatibility

These changes are fully backwards-compatible:

1. All new fields are optional. Existing agents and servers that do not understand the new fields will ignore them.
2. New capability bits are additive. Servers that do not check for the new bits will not set them and will not sign payloads.
3. Agents that do not declare `VerifiesRemoteConfigSignature` or `VerifiesPackageSignatures` will receive and apply configs and packages exactly as they do today, even if the server populates the new signature fields.

## Regenerating the Go Code

Once this change is merged into `opamp-spec`, regenerate the Go bindings:

```bash
# In the opamp-go repository root
protoc --go_out=. --go_opt=paths=source_relative \
  protobufs/opamp.proto protobufs/anyvalue.proto
```

Until the upstream PR is merged, the `protobufs/opamp.pb.go` file in this
repository contains the new fields added manually, consistent with this proposal.
