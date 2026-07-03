package signing

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestValidateChain_HappyPath_NoIntermediates exercises the simplest
// chain: leaf signed directly by the trust anchor.
func TestValidateChain_HappyPath_NoIntermediates(t *testing.T) {
	ca, caKey, err := GenerateCA(AlgorithmECDSAP256SHA256, CertOptions{})
	require.NoError(t, err)
	leaf, _, err := GenerateLeaf(AlgorithmECDSAP256SHA256, ca, caKey, CertOptions{})
	require.NoError(t, err)

	roots := x509.NewCertPool()
	roots.AddCert(ca)

	got, err := ValidateChain(context.Background(), [][]byte{leaf.Raw}, roots, time.Now())
	require.NoError(t, err)
	require.Equal(t, leaf.SerialNumber, got.SerialNumber)
}

// TestValidateChain_HappyPath_WithIntermediate exercises a chain with
// one intermediate CA between the root and the leaf.
func TestValidateChain_HappyPath_WithIntermediate(t *testing.T) {
	rootCA, rootKey, err := GenerateCA(AlgorithmECDSAP256SHA256, CertOptions{CommonName: "Test Root"})
	require.NoError(t, err)
	intermediate, intermediateKey, err := generateIntermediate(t, AlgorithmECDSAP256SHA256, rootCA, rootKey)
	require.NoError(t, err)
	leaf, _, err := GenerateLeaf(AlgorithmECDSAP256SHA256, intermediate, intermediateKey, CertOptions{})
	require.NoError(t, err)

	roots := x509.NewCertPool()
	roots.AddCert(rootCA)

	got, err := ValidateChain(context.Background(), [][]byte{intermediate.Raw, leaf.Raw}, roots, time.Now())
	require.NoError(t, err)
	require.Equal(t, leaf.SerialNumber, got.SerialNumber)
}

// TestValidateChain_EmptyChain confirms the empty-chain sentinel
// error.
func TestValidateChain_EmptyChain(t *testing.T) {
	roots := x509.NewCertPool()
	_, err := ValidateChain(context.Background(), nil, roots, time.Now())
	require.ErrorIs(t, err, ErrEmptyChain)
}

// TestValidateChain_NilRoots returns ErrChainValidation rather than
// panicking when the trust anchor pool is missing.
func TestValidateChain_NilRoots(t *testing.T) {
	ca, caKey, err := GenerateCA(AlgorithmECDSAP256SHA256, CertOptions{})
	require.NoError(t, err)
	leaf, _, err := GenerateLeaf(AlgorithmECDSAP256SHA256, ca, caKey, CertOptions{})
	require.NoError(t, err)

	_, err = ValidateChain(context.Background(), [][]byte{leaf.Raw}, nil, time.Now())
	require.ErrorIs(t, err, ErrChainValidation)
}

// TestValidateChain_GarbageBytes confirms ErrParseCertificate when a
// chain entry isn't a valid DER certificate.
func TestValidateChain_GarbageBytes(t *testing.T) {
	roots := x509.NewCertPool()
	_, err := ValidateChain(context.Background(), [][]byte{{0xde, 0xad, 0xbe, 0xef}}, roots, time.Now())
	require.ErrorIs(t, err, ErrParseCertificate)
}

// TestValidateChain_UnknownRoot confirms that a chain whose root is
// not in the agent's trust pool is rejected.
func TestValidateChain_UnknownRoot(t *testing.T) {
	serverCA, serverKey, err := GenerateCA(AlgorithmECDSAP256SHA256, CertOptions{})
	require.NoError(t, err)
	leaf, _, err := GenerateLeaf(AlgorithmECDSAP256SHA256, serverCA, serverKey, CertOptions{})
	require.NoError(t, err)

	// Agent's trust pool — a different CA entirely.
	agentCA, _, err := GenerateCA(AlgorithmECDSAP256SHA256, CertOptions{})
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(agentCA)

	_, err = ValidateChain(context.Background(), [][]byte{leaf.Raw}, roots, time.Now())
	require.ErrorIs(t, err, ErrChainValidation)
}

// TestValidateChain_ExpiredLeaf confirms that expired leaves are
// rejected.
func TestValidateChain_ExpiredLeaf(t *testing.T) {
	ca, caKey, err := GenerateCA(AlgorithmECDSAP256SHA256, CertOptions{})
	require.NoError(t, err)
	leaf, _, err := GenerateLeaf(AlgorithmECDSAP256SHA256, ca, caKey, CertOptions{
		NotBefore: time.Now().Add(-48 * time.Hour),
		NotAfter:  time.Now().Add(-24 * time.Hour),
	})
	require.NoError(t, err)

	roots := x509.NewCertPool()
	roots.AddCert(ca)

	_, err = ValidateChain(context.Background(), [][]byte{leaf.Raw}, roots, time.Now())
	require.ErrorIs(t, err, ErrChainValidation)
}

// TestValidateChain_NotYetValidLeaf confirms that leaves whose
// NotBefore is in the future are rejected.
func TestValidateChain_NotYetValidLeaf(t *testing.T) {
	ca, caKey, err := GenerateCA(AlgorithmECDSAP256SHA256, CertOptions{})
	require.NoError(t, err)
	leaf, _, err := GenerateLeaf(AlgorithmECDSAP256SHA256, ca, caKey, CertOptions{
		NotBefore: time.Now().Add(24 * time.Hour),
		NotAfter:  time.Now().Add(48 * time.Hour),
	})
	require.NoError(t, err)

	roots := x509.NewCertPool()
	roots.AddCert(ca)

	_, err = ValidateChain(context.Background(), [][]byte{leaf.Raw}, roots, time.Now())
	require.ErrorIs(t, err, ErrChainValidation)
}

// TestValidateChain_LeafMissingEKU confirms that a cert without
// id-kp-codeSigning is rejected. This is the load-bearing check that
// prevents a TLS server certificate from being repurposed to sign
// OpAMP messages.
func TestValidateChain_LeafMissingEKU(t *testing.T) {
	ca, caKey, err := GenerateCA(AlgorithmECDSAP256SHA256, CertOptions{})
	require.NoError(t, err)
	leaf, _, err := generateLeafWithEKU(t, AlgorithmECDSAP256SHA256, ca, caKey,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	require.NoError(t, err)

	roots := x509.NewCertPool()
	roots.AddCert(ca)

	_, err = ValidateChain(context.Background(), [][]byte{leaf.Raw}, roots, time.Now())
	require.ErrorIs(t, err, ErrChainValidation)
}

// generateIntermediate produces a CA-capable intermediate certificate
// signed by the supplied root, using the requested algorithm for the
// intermediate's own key. The public GenerateLeaf in certs.go is for
// non-CA leaves, so the test file needs its own helper.
func generateIntermediate(t *testing.T, alg Algorithm, root *x509.Certificate, rootKey crypto.Signer) (*x509.Certificate, crypto.Signer, error) {
	t.Helper()
	intermediateKey, sigAlg, intermediatePub, err := newKey(alg)
	if err != nil {
		return nil, nil, err
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "opamp-go test intermediate"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
		SignatureAlgorithm:    sigAlg,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, root, intermediatePub, rootKey)
	if err != nil {
		return nil, nil, err
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return parsed, intermediateKey, nil
}

// generateLeafWithEKU produces a leaf certificate with the supplied
// ExtKeyUsage set (and only that — code signing is intentionally
// absent for tests that want to verify EKU enforcement). Otherwise
// it mirrors GenerateLeaf.
func generateLeafWithEKU(t *testing.T, alg Algorithm, ca *x509.Certificate, caKey crypto.Signer, ekus []x509.ExtKeyUsage) (*x509.Certificate, crypto.Signer, error) {
	t.Helper()
	leafKey, sigAlg, leafPub, err := newKey(alg)
	if err != nil {
		return nil, nil, err
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber:       serial,
		Subject:            pkix.Name{CommonName: "opamp-go test wrong-EKU leaf"},
		NotBefore:          time.Now().Add(-1 * time.Hour),
		NotAfter:           time.Now().Add(24 * time.Hour),
		KeyUsage:           x509.KeyUsageDigitalSignature,
		ExtKeyUsage:        ekus,
		SignatureAlgorithm: sigAlg,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, leafPub, caKey)
	if err != nil {
		return nil, nil, err
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return parsed, leafKey, nil
}
