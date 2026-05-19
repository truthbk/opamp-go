package signing

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestNewLocalSigner_NilKey rejects a nil private key.
func TestNewLocalSigner_NilKey(t *testing.T) {
	ca, _, err := GenerateCA(AlgorithmECDSAP256SHA256, CertOptions{})
	require.NoError(t, err)
	_, err = NewLocalSigner(nil, []*x509.Certificate{ca})
	require.ErrorIs(t, err, ErrNilKey)
}

// TestNewLocalSigner_EmptyChain rejects an empty chain.
func TestNewLocalSigner_EmptyChain(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	_, err = NewLocalSigner(key, nil)
	require.ErrorIs(t, err, ErrEmptyChain)
}

// TestNewLocalSigner_UnsupportedLeafAlgorithm rejects a leaf whose
// SignatureAlgorithm is outside the supported set.
func TestNewLocalSigner_UnsupportedLeafAlgorithm(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	bogusLeaf := &x509.Certificate{SignatureAlgorithm: x509.MD5WithRSA, Raw: []byte{0x01}}
	_, err = NewLocalSigner(key, []*x509.Certificate{bogusLeaf})
	require.ErrorIs(t, err, ErrUnsupportedAlgorithm)
}

// TestLocalSigner_ChainDERDefensiveCopy confirms the signer returns a
// fresh copy that callers can mutate without disturbing the signer's
// internal state.
func TestLocalSigner_ChainDERDefensiveCopy(t *testing.T) {
	_, signer, _ := testKeyPair(t, AlgorithmECDSAP256SHA256)

	c1, err := signer.ChainDER(context.Background())
	require.NoError(t, err)
	require.Len(t, c1, 1)

	// Mutate the returned slice.
	c1[0][0] ^= 0xff

	// A second call must still return the original bytes.
	c2, err := signer.ChainDER(context.Background())
	require.NoError(t, err)
	require.Len(t, c2, 1)
	require.NotEqual(t, c1[0][0], c2[0][0], "second ChainDER call must not see caller mutations to first")
}

// TestLocalSigner_AlgorithmAccessor confirms the diagnostic accessor.
func TestLocalSigner_AlgorithmAccessor(t *testing.T) {
	for _, alg := range allAlgorithms {
		t.Run(alg.String(), func(t *testing.T) {
			_, signer, _ := testKeyPair(t, alg)
			require.Equal(t, alg, signer.Algorithm())
		})
	}
}
