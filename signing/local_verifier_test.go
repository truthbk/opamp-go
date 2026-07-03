package signing

import (
	"context"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestNewLocalVerifier_NilRoots rejects a nil trust anchor pool.
func TestNewLocalVerifier_NilRoots(t *testing.T) {
	_, err := NewLocalVerifier(nil)
	require.ErrorIs(t, err, ErrNilRoots)
}

// TestLocalVerifier_VerifyNilLeaf rejects a nil leaf, since
// signature verification fundamentally needs a public key.
func TestLocalVerifier_VerifyNilLeaf(t *testing.T) {
	roots := x509.NewCertPool()
	v, err := NewLocalVerifier(roots)
	require.NoError(t, err)
	err = v.Verify(context.Background(), []byte("payload"), []byte("sig"), nil)
	require.Error(t, err)
}

// TestLocalVerifier_VerifyEmptySignature rejects empty signatures —
// the OpAMP spec mandates signature be present and non-empty on every
// message after the handshake.
func TestLocalVerifier_VerifyEmptySignature(t *testing.T) {
	ca, caKey, err := GenerateCA(AlgorithmECDSAP256SHA256, CertOptions{})
	require.NoError(t, err)
	leaf, _, err := GenerateLeaf(AlgorithmECDSAP256SHA256, ca, caKey, CertOptions{})
	require.NoError(t, err)

	roots := x509.NewCertPool()
	roots.AddCert(ca)
	v, err := NewLocalVerifier(roots)
	require.NoError(t, err)
	err = v.Verify(context.Background(), []byte("payload"), nil, leaf)
	require.Error(t, err)
}
