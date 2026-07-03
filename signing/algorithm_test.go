package signing

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// allAlgorithms is the set of algorithms the package is required to
// support. Tests that exercise the algorithm-dispatch path table-drive
// across these.
var allAlgorithms = []Algorithm{
	AlgorithmECDSAP256SHA256,
	AlgorithmECDSAP384SHA384,
	AlgorithmRSAPKCS1v15SHA256,
	AlgorithmEd25519,
}

// testKeyPair generates a fresh CA + leaf pair for the supplied
// algorithm, returning the leaf, leaf's signing key, and a trust anchor
// pool containing the CA. It's the workhorse for round-trip tests.
func testKeyPair(t *testing.T, alg Algorithm) (*x509.Certificate, *LocalSigner, *LocalVerifier) {
	t.Helper()
	ca, caKey, err := GenerateCA(alg, CertOptions{})
	require.NoError(t, err)
	leaf, leafKey, err := GenerateLeaf(alg, ca, caKey, CertOptions{})
	require.NoError(t, err)

	signer, err := NewLocalSigner(leafKey, []*x509.Certificate{leaf})
	require.NoError(t, err)

	roots := x509.NewCertPool()
	roots.AddCert(ca)
	verifier, err := NewLocalVerifier(roots)
	require.NoError(t, err)

	return leaf, signer, verifier
}

// TestRoundTrip_AllAlgorithms exercises the happy path across every
// supported algorithm: sign a payload via LocalSigner, validate the
// chain and verify the signature via LocalVerifier.
func TestRoundTrip_AllAlgorithms(t *testing.T) {
	ctx := context.Background()
	payload := []byte("OpAMP Message Attestation round-trip payload")

	for _, alg := range allAlgorithms {
		t.Run(alg.String(), func(t *testing.T) {
			_, signer, verifier := testKeyPair(t, alg)
			assert.Equal(t, alg, signer.Algorithm())

			sig, err := signer.Sign(ctx, payload)
			require.NoError(t, err)
			require.NotEmpty(t, sig)

			chainDER, err := signer.ChainDER(ctx)
			require.NoError(t, err)
			require.Len(t, chainDER, 1, "chain should be just the leaf (no intermediates in the simple case)")

			leaf, err := verifier.ValidateChain(ctx, chainDER, time.Now())
			require.NoError(t, err)
			require.NotNil(t, leaf)

			require.NoError(t, verifier.Verify(ctx, payload, sig, leaf))
		})
	}
}

// TestTamperedSignature_AllAlgorithms confirms that flipping a single
// byte in the signature is detected as ErrSignatureMismatch (or for
// RSA, wrapped by ErrSignatureMismatch since the stdlib returns a
// distinct internal error).
func TestTamperedSignature_AllAlgorithms(t *testing.T) {
	ctx := context.Background()
	payload := []byte("payload to sign")

	for _, alg := range allAlgorithms {
		t.Run(alg.String(), func(t *testing.T) {
			_, signer, verifier := testKeyPair(t, alg)
			sig, err := signer.Sign(ctx, payload)
			require.NoError(t, err)
			require.NotEmpty(t, sig)

			tampered := append([]byte(nil), sig...)
			tampered[len(tampered)-1] ^= 0x01

			chainDER, err := signer.ChainDER(ctx)
			require.NoError(t, err)
			leaf, err := verifier.ValidateChain(ctx, chainDER, time.Now())
			require.NoError(t, err)

			err = verifier.Verify(ctx, payload, tampered, leaf)
			require.Error(t, err)
			require.ErrorIs(t, err, ErrSignatureMismatch)
		})
	}
}

// TestTamperedPayload_AllAlgorithms confirms that flipping a single
// byte of the payload makes the original signature invalid.
func TestTamperedPayload_AllAlgorithms(t *testing.T) {
	ctx := context.Background()
	payload := []byte("payload to sign")

	for _, alg := range allAlgorithms {
		t.Run(alg.String(), func(t *testing.T) {
			_, signer, verifier := testKeyPair(t, alg)
			sig, err := signer.Sign(ctx, payload)
			require.NoError(t, err)

			tampered := append([]byte(nil), payload...)
			tampered[0] ^= 0x01

			chainDER, err := signer.ChainDER(ctx)
			require.NoError(t, err)
			leaf, err := verifier.ValidateChain(ctx, chainDER, time.Now())
			require.NoError(t, err)

			err = verifier.Verify(ctx, tampered, sig, leaf)
			require.Error(t, err)
			require.ErrorIs(t, err, ErrSignatureMismatch)
		})
	}
}

// TestEmptySignatureRejected confirms that the Verifier refuses to
// even attempt verification when the signature is empty — the wire
// spec requires signature to be present and non-empty on every
// message after the handshake.
func TestEmptySignatureRejected(t *testing.T) {
	ctx := context.Background()
	_, _, verifier := testKeyPair(t, AlgorithmECDSAP256SHA256)
	// Need a valid leaf to pass the early nil check.
	ca, caKey, err := GenerateCA(AlgorithmECDSAP256SHA256, CertOptions{})
	require.NoError(t, err)
	leaf, _, err := GenerateLeaf(AlgorithmECDSAP256SHA256, ca, caKey, CertOptions{})
	require.NoError(t, err)

	err = verifier.Verify(ctx, []byte("payload"), nil, leaf)
	require.Error(t, err)
}

// TestContextCancellationPropagates confirms that a cancelled context
// is honoured by Sign, ChainDER, ValidateChain, and Verify.
func TestContextCancellationPropagates(t *testing.T) {
	_, signer, verifier := testKeyPair(t, AlgorithmECDSAP256SHA256)
	chainDER, err := signer.ChainDER(context.Background())
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = signer.Sign(ctx, []byte("x"))
	require.ErrorIs(t, err, context.Canceled)

	_, err = signer.ChainDER(ctx)
	require.ErrorIs(t, err, context.Canceled)

	_, err = verifier.ValidateChain(ctx, chainDER, time.Now())
	require.ErrorIs(t, err, context.Canceled)

	err = verifier.Verify(ctx, []byte("x"), []byte("y"), nil)
	require.ErrorIs(t, err, context.Canceled)
}

// TestUnsupportedAlgorithmFromCert confirms that algorithmFromCert
// rejects unsupported algorithms.
func TestUnsupportedAlgorithmFromCert(t *testing.T) {
	// Forge a cert with an unsupported SignatureAlgorithm.
	cert := &x509.Certificate{SignatureAlgorithm: x509.MD5WithRSA}
	_, err := algorithmFromCert(cert)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrUnsupportedAlgorithm), "expected ErrUnsupportedAlgorithm, got %v", err)
}

// TestAlgorithmString covers Algorithm.String for diagnostic output.
func TestAlgorithmString(t *testing.T) {
	cases := []struct {
		alg  Algorithm
		want string
	}{
		{AlgorithmECDSAP256SHA256, "ECDSA-P256-SHA256"},
		{AlgorithmECDSAP384SHA384, "ECDSA-P384-SHA384"},
		{AlgorithmRSAPKCS1v15SHA256, "RSA-PKCS1v15-SHA256"},
		{AlgorithmEd25519, "Ed25519"},
		{AlgorithmUnspecified, "unspecified"},
		{Algorithm(99), "unspecified"},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, tc.alg.String())
	}
}
