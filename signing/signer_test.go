package signing_test

import (
	"crypto/rand"
	"crypto/rsa"
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

func TestConfigSigner_RoundTrip(t *testing.T) {
	fx := newSigningFixtures(t)
	config := sampleConfig()
	require.NoError(t, fx.configSigner.SignConfig(config))
	assert.NotEmpty(t, config.Signature)
	assert.NotEmpty(t, config.SigningCertChain)
	assert.NoError(t, fx.verifier.VerifyRemoteConfig(config))
}

func TestFileSigner_RoundTrip(t *testing.T) {
	fx := newSigningFixtures(t)
	content := []byte("binary artifact v1.2.3")
	file := &protobufs.DownloadableFile{
		DownloadUrl: "https://example.com/pkg.tar.gz",
		ContentHash: []byte("sha256-deadbeef"),
	}
	require.NoError(t, fx.fileSigner.SignFile(file, content))
	assert.NotEmpty(t, file.Signature)
	assert.NotEmpty(t, file.SigningCertChain)
	assert.NoError(t, fx.verifier.VerifyFile(file, content))
}

func TestConfigSigner_RejectsRSAKey(t *testing.T) {
	// NewConfigSigner and NewFileSigner must return an error when given an RSA key
	// rather than an ECDSA key.
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "rsa-test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &rsaKey.PublicKey, rsaKey)
	require.NoError(t, err)

	certPEM := pem.Block{Type: "CERTIFICATE", Bytes: certDER}
	keyDER, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	require.NoError(t, err)
	keyPEM := pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}

	tlsCert, err := tls.X509KeyPair(pem.EncodeToMemory(&certPEM), pem.EncodeToMemory(&keyPEM))
	require.NoError(t, err)

	_, err = signing.NewConfigSigner(&tlsCert, pem.EncodeToMemory(&certPEM))
	assert.ErrorContains(t, err, "ECDSA")

	_, err = signing.NewFileSigner(&tlsCert, pem.EncodeToMemory(&certPEM))
	assert.ErrorContains(t, err, "ECDSA")
}
