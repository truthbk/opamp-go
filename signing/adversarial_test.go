package signing

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestVerify_LeafPublicKeyMismatch is the load-bearing security test:
// a signature produced by private key A must not verify when the leaf
// certificate carries the public key of a different key B. This is
// the spoofing scenario the verifier is designed to defeat — bugs in
// algorithm dispatch (e.g., reading cert.SignatureAlgorithm instead of
// dispatching on the leaf's actual pubkey) would let it succeed.
func TestVerify_LeafPublicKeyMismatch(t *testing.T) {
	ctx := context.Background()
	payload := []byte("payload")

	// Build two independent CA + leaf pairs with the same algorithm.
	caA, caAKey, err := GenerateCA(AlgorithmECDSAP256SHA256, CertOptions{CommonName: "CA-A"})
	require.NoError(t, err)
	leafA, leafAKey, err := GenerateLeaf(AlgorithmECDSAP256SHA256, caA, caAKey, CertOptions{CommonName: "leaf-A"})
	require.NoError(t, err)

	caB, caBKey, err := GenerateCA(AlgorithmECDSAP256SHA256, CertOptions{CommonName: "CA-B"})
	require.NoError(t, err)
	leafB, _, err := GenerateLeaf(AlgorithmECDSAP256SHA256, caB, caBKey, CertOptions{CommonName: "leaf-B"})
	require.NoError(t, err)

	signerA, err := NewLocalSigner(leafAKey, []*x509.Certificate{leafA})
	require.NoError(t, err)
	sig, err := signerA.Sign(ctx, payload)
	require.NoError(t, err)

	// Verifier with B's CA pool, asked to verify A's signature against
	// leaf B's public key. Must reject.
	rootsB := x509.NewCertPool()
	rootsB.AddCert(caB)
	verifierB, err := NewLocalVerifier(rootsB)
	require.NoError(t, err)

	err = verifierB.Verify(ctx, payload, sig, leafB)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrSignatureMismatch)
}

// TestVerify_AlgorithmFamilyMismatch confirms the verifier rejects an
// ECDSA signature presented against an RSA leaf and vice versa — even
// though both algorithms are in the supported set, mixing them must
// fail.
func TestVerify_AlgorithmFamilyMismatch(t *testing.T) {
	ctx := context.Background()
	payload := []byte("payload")

	// ECDSA signer.
	caEc, caEcKey, err := GenerateCA(AlgorithmECDSAP256SHA256, CertOptions{})
	require.NoError(t, err)
	leafEc, leafEcKey, err := GenerateLeaf(AlgorithmECDSAP256SHA256, caEc, caEcKey, CertOptions{})
	require.NoError(t, err)
	ecSigner, err := NewLocalSigner(leafEcKey, []*x509.Certificate{leafEc})
	require.NoError(t, err)
	ecSig, err := ecSigner.Sign(ctx, payload)
	require.NoError(t, err)

	// RSA leaf to present to the verifier.
	caRsa, caRsaKey, err := GenerateCA(AlgorithmRSAPKCS1v15SHA256, CertOptions{})
	require.NoError(t, err)
	leafRsa, _, err := GenerateLeaf(AlgorithmRSAPKCS1v15SHA256, caRsa, caRsaKey, CertOptions{})
	require.NoError(t, err)

	rootsRsa := x509.NewCertPool()
	rootsRsa.AddCert(caRsa)
	verifier, err := NewLocalVerifier(rootsRsa)
	require.NoError(t, err)

	// ECDSA signature, RSA leaf → must reject. Verifier dispatches on
	// the RSA leaf's pubkey type, so we end up in the RSA branch trying
	// to verify ECDSA-DER bytes as a PKCS#1 v1.5 signature, which
	// always returns ErrSignatureMismatch.
	err = verifier.Verify(ctx, payload, ecSig, leafRsa)
	require.ErrorIs(t, err, ErrSignatureMismatch)
}

// TestWrongChainOrder_DetectedAtSignatureVerify documents how the
// package handles a chain delivered in the wrong order
// ([leaf, intermediate] instead of the spec-mandated
// [intermediate, leaf]). ValidateChain takes the last entry as the
// leaf, so a wrong-order chain returns the intermediate's certificate
// as "leaf". Standard X.509 verification accepts that because the
// intermediate is also a CA-capable cert signed by the root, and
// Go's x509 library does not require an explicit EKU when none is
// declared on the cert.
//
// The actual defence against wrong-ordered chains is the per-message
// signature step: the server signs with the *real* leaf's private
// key, but the wrong-order chain delivers the intermediate's public
// key to the verifier. Subsequent signature verifications therefore
// fail. This test exercises exactly that path.
//
// The lesson for downstream signer implementations (LocalSigner and
// any RPC-backed equivalent): the order of bytes in ChainDER is
// load-bearing for signature verification, even when X.509 path
// validation succeeds in spite of it.
func TestWrongChainOrder_DetectedAtSignatureVerify(t *testing.T) {
	ctx := context.Background()
	rootCA, rootKey, err := GenerateCA(AlgorithmECDSAP256SHA256, CertOptions{CommonName: "Root"})
	require.NoError(t, err)
	intermediate, intermediateKey, err := generateIntermediate(t, AlgorithmECDSAP256SHA256, rootCA, rootKey)
	require.NoError(t, err)
	leaf, leafKey, err := GenerateLeaf(AlgorithmECDSAP256SHA256, intermediate, intermediateKey, CertOptions{})
	require.NoError(t, err)

	// The signer holds the REAL leaf's private key and produces a
	// signature with it. The wrong-order chain delivery is purely a
	// receive-side framing issue.
	signer, err := NewLocalSigner(leafKey, []*x509.Certificate{intermediate, leaf})
	require.NoError(t, err)
	payload := []byte("payload")
	sig, err := signer.Sign(ctx, payload)
	require.NoError(t, err)

	roots := x509.NewCertPool()
	roots.AddCert(rootCA)
	verifier, err := NewLocalVerifier(roots)
	require.NoError(t, err)

	// Correct order: validate succeeds, verify succeeds.
	correctLeaf, err := verifier.ValidateChain(ctx, [][]byte{intermediate.Raw, leaf.Raw}, time.Now())
	require.NoError(t, err)
	require.NoError(t, verifier.Verify(ctx, payload, sig, correctLeaf))

	// Wrong order: ValidateChain returns the *intermediate* as the
	// "leaf" (Go's x509 doesn't reject it for EKU absence), but the
	// signature was produced by the real leaf's private key, so verify
	// against the intermediate's pubkey fails.
	wrongLeaf, err := verifier.ValidateChain(ctx, [][]byte{leaf.Raw, intermediate.Raw}, time.Now())
	require.NoError(t, err, "chain validation is structurally permissive about leaf identity; the spec-level protection lives at signature verify time")
	require.NotEqual(t, leaf.SerialNumber, wrongLeaf.SerialNumber, "validate returned the intermediate as leaf, not the real leaf")

	err = verifier.Verify(ctx, payload, sig, wrongLeaf)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrSignatureMismatch, "wrong-ordered chain produces a signature-verification failure")
}

// TestValidateChain_IntermediateNotSignedByRoot confirms a chain where
// the intermediate's issuer does not match any anchor in the trust
// pool is rejected.
func TestValidateChain_IntermediateNotSignedByRoot(t *testing.T) {
	// Agent's trusted root.
	trustedRoot, _, err := GenerateCA(AlgorithmECDSAP256SHA256, CertOptions{CommonName: "Trusted Root"})
	require.NoError(t, err)

	// Attacker's parallel root, intermediate, and leaf — entirely
	// outside the agent's trust pool.
	attackerRoot, attackerRootKey, err := GenerateCA(AlgorithmECDSAP256SHA256, CertOptions{CommonName: "Attacker Root"})
	require.NoError(t, err)
	attackerIntermediate, attackerIntermediateKey, err := generateIntermediate(t, AlgorithmECDSAP256SHA256, attackerRoot, attackerRootKey)
	require.NoError(t, err)
	attackerLeaf, _, err := GenerateLeaf(AlgorithmECDSAP256SHA256, attackerIntermediate, attackerIntermediateKey, CertOptions{})
	require.NoError(t, err)

	roots := x509.NewCertPool()
	roots.AddCert(trustedRoot)

	// Attacker presents chain rooted in their own CA.
	_, err = ValidateChain(context.Background(), [][]byte{attackerIntermediate.Raw, attackerLeaf.Raw}, roots, time.Now())
	require.Error(t, err)
	require.ErrorIs(t, err, ErrChainValidation)
}

// TestNewLocalSigner_LeafPublicKeyMismatchDetected confirms that
// constructing a LocalSigner where the supplied private key does not
// correspond to the leaf cert's public key produces signatures that
// fail to verify — protecting operators from an accidental
// configuration where keys and certs are mismatched (the kind of
// thing that would only surface at first-message time and look like
// a Verifier bug).
func TestNewLocalSigner_LeafPublicKeyMismatchDetected(t *testing.T) {
	// NOTE: LocalSigner doesn't validate key↔leaf consistency at
	// construction (a deliberate trade-off — see signing/local_signer.go).
	// This test instead asserts the observable symptom: a Sign + Verify
	// round-trip fails when the key doesn't match the leaf's pubkey.
	ctx := context.Background()

	ca, caKey, err := GenerateCA(AlgorithmECDSAP256SHA256, CertOptions{})
	require.NoError(t, err)
	leaf, _, err := GenerateLeaf(AlgorithmECDSAP256SHA256, ca, caKey, CertOptions{})
	require.NoError(t, err)

	// Wrong key — fresh ECDSA-P256 not bound to leaf.
	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	signer, err := NewLocalSigner(wrongKey, []*x509.Certificate{leaf})
	require.NoError(t, err) // construction is permissive

	sig, err := signer.Sign(ctx, []byte("payload"))
	require.NoError(t, err)

	roots := x509.NewCertPool()
	roots.AddCert(ca)
	verifier, err := NewLocalVerifier(roots)
	require.NoError(t, err)
	validatedLeaf, err := verifier.ValidateChain(ctx, [][]byte{leaf.Raw}, time.Now())
	require.NoError(t, err)
	err = verifier.Verify(ctx, []byte("payload"), sig, validatedLeaf)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrSignatureMismatch)
}

// TestParseCertChainPEM_IgnoresNonCertificateBlocks confirms that a
// chain bundle with stray PEM blocks (e.g. a private key accidentally
// left in the chain file) is parsed correctly — non-CERTIFICATE
// blocks are skipped, and the certificates that ARE present load.
func TestParseCertChainPEM_IgnoresNonCertificateBlocks(t *testing.T) {
	ca, caKey, err := GenerateCA(AlgorithmECDSAP256SHA256, CertOptions{})
	require.NoError(t, err)
	leaf, _, err := GenerateLeaf(AlgorithmECDSAP256SHA256, ca, caKey, CertOptions{})
	require.NoError(t, err)

	// Build a chain bundle with an arbitrary non-CERTIFICATE block
	// (the realistic mis-bundling: an operator pastes a PRIVATE KEY
	// block into the chain file). Use the CA's actual PKCS#8 key
	// bytes so the junk block is well-formed PEM, not random bytes.
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})
	keyDER, err := x509.MarshalPKCS8PrivateKey(caKey)
	require.NoError(t, err)
	junkPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	combined := append(append([]byte{}, leafPEM...), junkPEM...)

	chain, err := parseCertChainPEM(combined)
	require.NoError(t, err)
	require.Len(t, chain, 1, "non-CERTIFICATE block should be skipped, only leaf remains")
	require.Equal(t, leaf.SerialNumber, chain[0].SerialNumber)
}

// TestAlgorithmFromCert_RSAKeyTooSmall confirms the minimum RSA
// modulus enforcement: a 1024-bit RSA key is rejected even if the
// declared SignatureAlgorithm matches.
func TestAlgorithmFromCert_RSAKeyTooSmall(t *testing.T) {
	// Generate a 1024-bit RSA leaf directly (bypassing GenerateLeaf
	// which would refuse — or rather, succeed since GenerateLeaf
	// uses 2048; we forge a 1024-bit one here).
	ca, caKey, err := GenerateCA(AlgorithmRSAPKCS1v15SHA256, CertOptions{})
	require.NoError(t, err)

	smallKey, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber:       serial,
		Subject:            pkix.Name{CommonName: "small-rsa-leaf"},
		NotBefore:          time.Now().Add(-1 * time.Hour),
		NotAfter:           time.Now().Add(24 * time.Hour),
		KeyUsage:           x509.KeyUsageDigitalSignature,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &smallKey.PublicKey, caKey)
	require.NoError(t, err)
	smallCert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	_, err = algorithmFromCert(smallCert)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrUnsupportedAlgorithm)
}

// TestAlgorithmFromCert_AlgorithmDeclarationMismatch confirms that a
// cert whose declared SignatureAlgorithm doesn't match its actual
// public-key type is rejected.
func TestAlgorithmFromCert_AlgorithmDeclarationMismatch(t *testing.T) {
	// Forge a cert with an ECDSA P-256 pubkey but SignatureAlgorithm
	// declared as ECDSAWithSHA384 (which is for P-384).
	caRoot, caRootKey, err := GenerateCA(AlgorithmECDSAP256SHA256, CertOptions{})
	require.NoError(t, err)
	wrongAlgKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber:       serial,
		Subject:            pkix.Name{CommonName: "mismatched-alg-leaf"},
		NotBefore:          time.Now().Add(-1 * time.Hour),
		NotAfter:           time.Now().Add(24 * time.Hour),
		KeyUsage:           x509.KeyUsageDigitalSignature,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		SignatureAlgorithm: x509.ECDSAWithSHA384, // intentionally wrong: P-256 key paired with SHA-384
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caRoot, &wrongAlgKey.PublicKey, caRootKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	_, err = algorithmFromCert(cert)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrUnsupportedAlgorithm)
}
