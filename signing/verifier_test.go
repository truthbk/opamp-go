package signing_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/open-telemetry/opamp-go/protobufs"
	"github.com/open-telemetry/opamp-go/signing"
)

// signingFixtures holds a ready-to-use signer + verifier pair.
type signingFixtures struct {
	caCertPEM    []byte
	configSigner *signing.ConfigSigner
	fileSigner   *signing.FileSigner
	verifier     *signing.X509SignatureVerifier
}

func newSigningFixtures(t *testing.T) *signingFixtures {
	t.Helper()
	caKey, caCert, caCertPEM, err := signing.GenerateECDSACA()
	require.NoError(t, err)

	leafTLS, leafChainPEM, err := signing.GenerateECDSALeafCert(caCert, caKey)
	require.NoError(t, err)

	cs, err := signing.NewConfigSigner(leafTLS, leafChainPEM)
	require.NoError(t, err)

	fs, err := signing.NewFileSigner(leafTLS, leafChainPEM)
	require.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caCertPEM)

	return &signingFixtures{
		caCertPEM:    caCertPEM,
		configSigner: cs,
		fileSigner:   fs,
		verifier:     signing.NewX509SignatureVerifier(pool),
	}
}

// generateCustomLeafCert creates a leaf cert with caller-controlled attributes
// for testing edge cases.
func generateCustomLeafCert(
	t *testing.T,
	ca *x509.Certificate,
	caKey *ecdsa.PrivateKey,
	notBefore, notAfter time.Time,
	ekus []x509.ExtKeyUsage,
) (*tls.Certificate, []byte) {
	t.Helper()

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test-leaf"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  ekus,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca, &leafKey.PublicKey, caKey)
	require.NoError(t, err)

	var certPEM, keyPEM bytes.Buffer
	require.NoError(t, pem.Encode(&certPEM, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	leafKeyDER, err := x509.MarshalECPrivateKey(leafKey)
	require.NoError(t, err)
	require.NoError(t, pem.Encode(&keyPEM, &pem.Block{Type: "EC PRIVATE KEY", Bytes: leafKeyDER}))

	tlsCert, err := tls.X509KeyPair(certPEM.Bytes(), keyPEM.Bytes())
	require.NoError(t, err)
	return &tlsCert, certPEM.Bytes()
}

func sampleConfig() *protobufs.AgentRemoteConfig {
	return &protobufs.AgentRemoteConfig{
		Config: &protobufs.AgentConfigMap{
			ConfigMap: map[string]*protobufs.AgentConfigFile{
				"app": {Body: []byte("key: value\n")},
			},
		},
		ConfigHash: []byte("sha256-abc123"),
	}
}

// --- Remote config verification ---

func TestVerifyRemoteConfig_Valid(t *testing.T) {
	fx := newSigningFixtures(t)
	config := sampleConfig()
	require.NoError(t, fx.configSigner.SignConfig(config))
	assert.NoError(t, fx.verifier.VerifyRemoteConfig(config))
}

func TestVerifyRemoteConfig_TamperedSig(t *testing.T) {
	fx := newSigningFixtures(t)
	config := sampleConfig()
	require.NoError(t, fx.configSigner.SignConfig(config))

	config.Signature[0] ^= 0xFF

	assert.Error(t, fx.verifier.VerifyRemoteConfig(config))
}

func TestVerifyRemoteConfig_TamperedConfig(t *testing.T) {
	fx := newSigningFixtures(t)
	config := sampleConfig()
	require.NoError(t, fx.configSigner.SignConfig(config))

	// Change config body after signing.
	config.Config.ConfigMap["app"].Body = []byte("tampered: true\n")

	assert.Error(t, fx.verifier.VerifyRemoteConfig(config))
}

func TestVerifyRemoteConfig_ExpiredCert(t *testing.T) {
	caKey, caCert, caCertPEM, err := signing.GenerateECDSACA()
	require.NoError(t, err)

	// Expired leaf: NotAfter is in the past.
	expired := time.Now().Add(-2 * time.Hour)
	leafTLS, leafChainPEM := generateCustomLeafCert(
		t, caCert, caKey,
		expired.Add(-time.Hour), expired,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	)

	cs, err := signing.NewConfigSigner(leafTLS, leafChainPEM)
	require.NoError(t, err)

	config := sampleConfig()
	require.NoError(t, cs.SignConfig(config))

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caCertPEM)
	verifier := signing.NewX509SignatureVerifier(pool)

	err = verifier.VerifyRemoteConfig(config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "certificate chain verification failed")
}

func TestVerifyRemoteConfig_UnknownCA(t *testing.T) {
	// Sign with CA-A, verify with CA-B trust pool.
	fx := newSigningFixtures(t) // uses CA-A

	config := sampleConfig()
	require.NoError(t, fx.configSigner.SignConfig(config))

	// Build a different CA for the verifier.
	_, _, otherCAPEM, err := signing.GenerateECDSACA()
	require.NoError(t, err)
	otherPool := x509.NewCertPool()
	otherPool.AppendCertsFromPEM(otherCAPEM)
	verifier := signing.NewX509SignatureVerifier(otherPool)

	assert.Error(t, verifier.VerifyRemoteConfig(config))
}

func TestVerifyRemoteConfig_WrongEKU(t *testing.T) {
	caKey, caCert, caCertPEM, err := signing.GenerateECDSACA()
	require.NoError(t, err)

	// Leaf has only ServerAuth EKU, not CodeSigning.
	leafTLS, leafChainPEM := generateCustomLeafCert(
		t, caCert, caKey,
		time.Now().Add(-time.Minute), time.Now().Add(24*time.Hour),
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	)

	cs, err := signing.NewConfigSigner(leafTLS, leafChainPEM)
	require.NoError(t, err)

	config := sampleConfig()
	require.NoError(t, cs.SignConfig(config))

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caCertPEM)
	verifier := signing.NewX509SignatureVerifier(pool)

	err = verifier.VerifyRemoteConfig(config)
	assert.Error(t, err)
}

func TestVerifyRemoteConfig_MissingSignature(t *testing.T) {
	fx := newSigningFixtures(t)
	config := sampleConfig()
	// Do NOT sign — Signature and SigningCertChain are nil.
	err := fx.verifier.VerifyRemoteConfig(config)
	assert.ErrorIs(t, err, signing.ErrMissingSignature)
}

// --- File verification ---

func TestVerifyFile_Valid(t *testing.T) {
	fx := newSigningFixtures(t)
	content := []byte("binary package content")
	file := &protobufs.DownloadableFile{ContentHash: []byte("hash")}
	require.NoError(t, fx.fileSigner.SignFile(file, content))
	assert.NoError(t, fx.verifier.VerifyFile(file, content))
}

func TestVerifyFile_TamperedContent(t *testing.T) {
	fx := newSigningFixtures(t)
	content := []byte("binary package content")
	file := &protobufs.DownloadableFile{}
	require.NoError(t, fx.fileSigner.SignFile(file, content))

	tamperedContent := []byte("different content")
	assert.Error(t, fx.verifier.VerifyFile(file, tamperedContent))
}

func TestVerifyFile_TamperedSig(t *testing.T) {
	fx := newSigningFixtures(t)
	content := []byte("binary package content")
	file := &protobufs.DownloadableFile{}
	require.NoError(t, fx.fileSigner.SignFile(file, content))

	file.Signature[0] ^= 0xFF
	assert.Error(t, fx.verifier.VerifyFile(file, content))
}

func TestVerifyFile_MissingSignature(t *testing.T) {
	fx := newSigningFixtures(t)
	file := &protobufs.DownloadableFile{}
	// No signature set.
	err := fx.verifier.VerifyFile(file, []byte("content"))
	assert.ErrorIs(t, err, signing.ErrMissingSignature)
}
