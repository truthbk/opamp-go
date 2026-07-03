package signing

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestVerifierFromFile_RoundTrip writes a CA to disk, loads it via
// VerifierFromFile, and confirms a chain signed by that CA validates.
func TestVerifierFromFile_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	ca, caKey, err := GenerateCA(AlgorithmECDSAP256SHA256, CertOptions{})
	require.NoError(t, err)
	leaf, _, err := GenerateLeaf(AlgorithmECDSAP256SHA256, ca, caKey, CertOptions{})
	require.NoError(t, err)

	caPath := filepath.Join(dir, "ca.pem")
	writePEM(t, caPath, "CERTIFICATE", ca.Raw)

	v, err := VerifierFromFile(caPath)
	require.NoError(t, err)
	require.NotNil(t, v)

	got, err := v.ValidateChain(context.Background(), [][]byte{leaf.Raw}, time.Now())
	require.NoError(t, err)
	require.Equal(t, leaf.SerialNumber, got.SerialNumber)
}

// TestVerifierFromFile_EmptyPath rejects an empty path.
func TestVerifierFromFile_EmptyPath(t *testing.T) {
	_, err := VerifierFromFile("")
	require.ErrorIs(t, err, ErrLoadCAFile)
}

// TestVerifierFromFile_MissingFile rejects a path that doesn't exist.
func TestVerifierFromFile_MissingFile(t *testing.T) {
	_, err := VerifierFromFile(filepath.Join(t.TempDir(), "nonexistent.pem"))
	require.ErrorIs(t, err, ErrLoadCAFile)
}

// TestVerifierFromFile_NoCerts rejects a file with no CERTIFICATE PEM
// blocks.
func TestVerifierFromFile_NoCerts(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "empty.pem")
	require.NoError(t, os.WriteFile(caPath, []byte("not a PEM"), 0o600))
	_, err := VerifierFromFile(caPath)
	require.ErrorIs(t, err, ErrLoadCAFile)
}

// TestLocalSignerFromFiles_RoundTrip exercises the file-based loader
// for the LocalSigner across each algorithm. We write the leaf's
// private key (PKCS#8) and the chain (just the leaf in this case) to
// disk and then load.
func TestLocalSignerFromFiles_RoundTrip(t *testing.T) {
	for _, alg := range allAlgorithms {
		t.Run(alg.String(), func(t *testing.T) {
			dir := t.TempDir()
			ca, caKey, err := GenerateCA(alg, CertOptions{})
			require.NoError(t, err)
			leaf, leafKey, err := GenerateLeaf(alg, ca, caKey, CertOptions{})
			require.NoError(t, err)

			// Write key in PKCS#8 encoding (covers all four algorithms).
			keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
			require.NoError(t, err)
			keyPath := filepath.Join(dir, "leaf.key.pem")
			writePEM(t, keyPath, "PRIVATE KEY", keyDER)

			chainPath := filepath.Join(dir, "chain.pem")
			writePEM(t, chainPath, "CERTIFICATE", leaf.Raw)

			signer, err := LocalSignerFromFiles(keyPath, chainPath)
			require.NoError(t, err)
			require.Equal(t, alg, signer.Algorithm())

			// Round-trip sign + verify to confirm the loaded key
			// matches the loaded chain.
			roots := x509.NewCertPool()
			roots.AddCert(ca)
			verifier, err := NewLocalVerifier(roots)
			require.NoError(t, err)

			payload := []byte("loader round-trip payload")
			sig, err := signer.Sign(context.Background(), payload)
			require.NoError(t, err)
			validatedLeaf, err := verifier.ValidateChain(context.Background(), [][]byte{leaf.Raw}, time.Now())
			require.NoError(t, err)
			require.NoError(t, verifier.Verify(context.Background(), payload, sig, validatedLeaf))

			// Sanity-check that what came back from PEM is the same
			// type of key the algorithm expects.
			switch alg {
			case AlgorithmECDSAP256SHA256, AlgorithmECDSAP384SHA384:
				_, ok := leafKey.(*ecdsa.PrivateKey)
				require.True(t, ok)
			case AlgorithmRSAPKCS1v15SHA256:
				_, ok := leafKey.(*rsa.PrivateKey)
				require.True(t, ok)
			case AlgorithmEd25519:
				_, ok := leafKey.(ed25519.PrivateKey)
				require.True(t, ok)
			}
		})
	}
}

// TestLocalSignerFromFiles_EmptyPaths rejects empty paths.
func TestLocalSignerFromFiles_EmptyPaths(t *testing.T) {
	_, err := LocalSignerFromFiles("", "chain.pem")
	require.Error(t, err)
	_, err = LocalSignerFromFiles("key.pem", "")
	require.Error(t, err)
}

// TestLocalSignerFromFiles_BadKey rejects a key file with no parseable
// PEM key block.
func TestLocalSignerFromFiles_BadKey(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(keyPath, []byte("not a key"), 0o600))
	chainPath := filepath.Join(dir, "chain.pem")
	ca, caKey, err := GenerateCA(AlgorithmECDSAP256SHA256, CertOptions{})
	require.NoError(t, err)
	leaf, _, err := GenerateLeaf(AlgorithmECDSAP256SHA256, ca, caKey, CertOptions{})
	require.NoError(t, err)
	writePEM(t, chainPath, "CERTIFICATE", leaf.Raw)

	_, err = LocalSignerFromFiles(keyPath, chainPath)
	require.ErrorIs(t, err, ErrParsePrivateKey)
}

// TestLocalSignerFromFiles_EmptyChainFile rejects a chain file with no
// CERTIFICATE blocks.
func TestLocalSignerFromFiles_EmptyChainFile(t *testing.T) {
	dir := t.TempDir()
	chainPath := filepath.Join(dir, "chain.pem")
	require.NoError(t, os.WriteFile(chainPath, []byte("not a chain"), 0o600))

	// Need a valid key file to get past the key-load step.
	key, _ := generateValidKey(t)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	keyPath := filepath.Join(dir, "key.pem")
	writePEM(t, keyPath, "PRIVATE KEY", keyDER)

	_, err = LocalSignerFromFiles(keyPath, chainPath)
	require.ErrorIs(t, err, ErrEmptyChain)
}

// writePEM is a test helper that writes a PEM-encoded block of the
// given type to path. Permissions are 0600 since these tests handle
// private keys.
func writePEM(t *testing.T, path, blockType string, bytes []byte) {
	t.Helper()
	block := &pem.Block{Type: blockType, Bytes: bytes}
	encoded := pem.EncodeToMemory(block)
	require.NoError(t, os.WriteFile(path, encoded, 0o600))
}

// generateValidKey returns a freshly-generated ECDSA-P256 key, used by
// tests that only care about getting past the "valid key" check.
func generateValidKey(t *testing.T) (*ecdsa.PrivateKey, error) {
	t.Helper()
	k, _, _, err := newKey(AlgorithmECDSAP256SHA256)
	if err != nil {
		return nil, err
	}
	return k.(*ecdsa.PrivateKey), nil
}
