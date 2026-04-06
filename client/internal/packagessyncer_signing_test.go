package internal

import (
	"context"
	"crypto/x509"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sharedinternal "github.com/open-telemetry/opamp-go/internal"
	"github.com/open-telemetry/opamp-go/protobufs"
	"github.com/open-telemetry/opamp-go/signing"
)

// makeSigningSetup generates a CA, leaf cert, ConfigSigner, FileSigner, and X509SignatureVerifier.
func makeSigningSetup(t *testing.T) (*signing.FileSigner, *signing.X509SignatureVerifier) {
	t.Helper()
	caKey, caCert, caCertPEM, err := signing.GenerateECDSACA()
	require.NoError(t, err)

	leafTLS, leafChainPEM, err := signing.GenerateECDSALeafCert(caCert, caKey)
	require.NoError(t, err)

	fs, err := signing.NewFileSigner(leafTLS, leafChainPEM)
	require.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caCertPEM)
	verifier := signing.NewX509SignatureVerifier(pool)

	return fs, verifier
}

// runSyncerWithSignature is a test helper that:
// 1. Starts an httptest server serving fileContent.
// 2. Optionally signs the DownloadableFile using fileSigner.
// 3. Runs the syncer doSync.
// 4. Returns the final PackageStatus and package state.
func runSyncerWithSignature(
	t *testing.T,
	fileContent []byte,
	fileSigner *signing.FileSigner,
	signatureVerifier signing.SignatureVerifier,
	capabilities protobufs.AgentCapabilities,
) *protobufs.PackageStatus {
	t.Helper()

	_, serverURL := createTestHTTPServer(t, fileContent)

	file := &protobufs.DownloadableFile{
		DownloadUrl: serverURL,
		ContentHash: []byte("test-hash"),
	}

	// Optionally sign the file.
	if fileSigner != nil {
		require.NoError(t, fileSigner.SignFile(file, fileContent))
	}

	packagesAvailable := &protobufs.PackagesAvailable{
		Packages: map[string]*protobufs.PackageAvailable{
			"testpkg": {
				Type:    protobufs.PackageType_PackageType_TopLevel,
				Version: "1.0.0",
				Hash:    []byte("pkg-hash"),
				File:    file,
			},
		},
		AllPackagesHash: []byte("all-hash"),
	}

	store := NewInMemPackagesStore()

	clientSyncedState := &ClientSyncedState{}
	clientSyncedState.SetCapabilities(&capabilities)

	s, err := NewPackagesSyncer(
		&sharedinternal.NopLogger{},
		packagesAvailable,
		NewMockSender(),
		clientSyncedState,
		store,
		&sync.Mutex{},
		time.Second,
		func(context.Context, *protobufs.DownloadableFile) (*http.Client, error) {
			return &http.Client{}, nil
		},
		signatureVerifier,
	)
	require.NoError(t, err)

	s.mux.Lock()
	require.NoError(t, s.initStatuses())
	require.NoError(t, s.clientSyncedState.SetPackageStatuses(s.statuses))
	s.doSync(context.Background())

	return s.statuses.Packages["testpkg"]
}

func TestPackageSyncer_ValidSignatureAccepted(t *testing.T) {
	content := []byte("valid package binary content")
	fileSigner, verifier := makeSigningSetup(t)

	caps := protobufs.AgentCapabilities_AgentCapabilities_AcceptsPackages |
		protobufs.AgentCapabilities_AgentCapabilities_ReportsPackageStatuses |
		protobufs.AgentCapabilities_AgentCapabilities_VerifiesPackageSignatures |
		protobufs.AgentCapabilities_AgentCapabilities_ReportsStatus

	status := runSyncerWithSignature(t, content, fileSigner, verifier, caps)
	require.NotNil(t, status)
	assert.Equal(t, protobufs.PackageStatusEnum_PackageStatusEnum_Installed, status.Status)
	assert.Empty(t, status.ErrorMessage)
}

func TestPackageSyncer_InvalidSignatureRejected(t *testing.T) {
	content := []byte("valid package binary content")
	fileSigner, _ := makeSigningSetup(t)

	caps := protobufs.AgentCapabilities_AgentCapabilities_AcceptsPackages |
		protobufs.AgentCapabilities_AgentCapabilities_ReportsPackageStatuses |
		protobufs.AgentCapabilities_AgentCapabilities_VerifiesPackageSignatures |
		protobufs.AgentCapabilities_AgentCapabilities_ReportsStatus

	// Use a verifier that trusts a different CA so the signature fails.
	_, _, otherCAPEM, err := signing.GenerateECDSACA()
	require.NoError(t, err)
	otherPool := x509.NewCertPool()
	otherPool.AppendCertsFromPEM(otherCAPEM)
	wrongVerifier := signing.NewX509SignatureVerifier(otherPool)

	status := runSyncerWithSignature(t, content, fileSigner, wrongVerifier, caps)
	require.NotNil(t, status)
	assert.Equal(t, protobufs.PackageStatusEnum_PackageStatusEnum_InstallFailed, status.Status)
	assert.Contains(t, status.ErrorMessage, "signature verification failed")
}

func TestPackageSyncer_MissingSignatureRejected(t *testing.T) {
	content := []byte("unsigned package content")
	_, verifier := makeSigningSetup(t) // use a real verifier

	caps := protobufs.AgentCapabilities_AgentCapabilities_AcceptsPackages |
		protobufs.AgentCapabilities_AgentCapabilities_ReportsPackageStatuses |
		protobufs.AgentCapabilities_AgentCapabilities_VerifiesPackageSignatures |
		protobufs.AgentCapabilities_AgentCapabilities_ReportsStatus

	// No fileSigner => Signature field left empty.
	status := runSyncerWithSignature(t, content, nil, verifier, caps)
	require.NotNil(t, status)
	assert.Equal(t, protobufs.PackageStatusEnum_PackageStatusEnum_InstallFailed, status.Status)
	assert.Contains(t, status.ErrorMessage, "signature verification failed")
}

func TestPackageSyncer_SignatureIgnoredWithoutCapability(t *testing.T) {
	content := []byte("package with no cap")

	// Sign with a signer but use a wrong verifier — but since the capability
	// is not set, verification is skipped entirely.
	fileSigner, _ := makeSigningSetup(t)
	_, _, otherCAPEM, err := signing.GenerateECDSACA()
	require.NoError(t, err)
	otherPool := x509.NewCertPool()
	otherPool.AppendCertsFromPEM(otherCAPEM)
	wrongVerifier := signing.NewX509SignatureVerifier(otherPool)

	// AcceptsPackages but NOT VerifiesPackageSignatures.
	caps := protobufs.AgentCapabilities_AgentCapabilities_AcceptsPackages |
		protobufs.AgentCapabilities_AgentCapabilities_ReportsPackageStatuses |
		protobufs.AgentCapabilities_AgentCapabilities_ReportsStatus

	status := runSyncerWithSignature(t, content, fileSigner, wrongVerifier, caps)
	require.NotNil(t, status)
	// Package should be installed because verification is skipped.
	assert.Equal(t, protobufs.PackageStatusEnum_PackageStatusEnum_Installed, status.Status)
}

func TestPackageSyncer_NilVerifierWithCapabilityFails(t *testing.T) {
	// When VerifiesPackageSignatures is declared but signatureVerifier is nil,
	// the syncer must hard-reject the install rather than silently skipping
	// verification. validateCapabilities prevents this at Start() time; this
	// test confirms the syncer also enforces the invariant as a safety net.
	content := []byte("pkg content")

	caps := protobufs.AgentCapabilities_AgentCapabilities_AcceptsPackages |
		protobufs.AgentCapabilities_AgentCapabilities_ReportsPackageStatuses |
		protobufs.AgentCapabilities_AgentCapabilities_VerifiesPackageSignatures |
		protobufs.AgentCapabilities_AgentCapabilities_ReportsStatus

	status := runSyncerWithSignature(t, content, nil, nil, caps)
	require.NotNil(t, status)
	assert.Equal(t, protobufs.PackageStatusEnum_PackageStatusEnum_InstallFailed, status.Status)
	assert.Contains(t, status.ErrorMessage, "SignatureVerifier is not configured")
}
