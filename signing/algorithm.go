package signing

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"fmt"
)

// ErrUnsupportedAlgorithm indicates that a certificate's
// SignatureAlgorithm is not in the supported set, or that the
// public/private key type does not match the requested algorithm.
var ErrUnsupportedAlgorithm = errors.New("signing: unsupported signature algorithm")

// algorithmFromCert maps x509.Certificate.SignatureAlgorithm to the
// package's Algorithm enum, returning ErrUnsupportedAlgorithm for any
// value outside the supported baseline.
func algorithmFromCert(cert *x509.Certificate) (Algorithm, error) {
	switch cert.SignatureAlgorithm {
	case x509.ECDSAWithSHA256:
		return AlgorithmECDSAP256SHA256, nil
	case x509.ECDSAWithSHA384:
		return AlgorithmECDSAP384SHA384, nil
	case x509.SHA256WithRSA:
		return AlgorithmRSAPKCS1v15SHA256, nil
	case x509.PureEd25519:
		return AlgorithmEd25519, nil
	default:
		return AlgorithmUnspecified, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, cert.SignatureAlgorithm)
	}
}

// signWithKey produces a detached signature over payload using key,
// dispatching on alg. The caller is responsible for matching alg to
// the type of key (private key types are not switchable at runtime).
func signWithKey(key crypto.Signer, alg Algorithm, payload []byte) ([]byte, error) {
	switch alg {
	case AlgorithmECDSAP256SHA256:
		k, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%w: ECDSA-P256 requires *ecdsa.PrivateKey, got %T", ErrUnsupportedAlgorithm, key)
		}
		h := sha256.Sum256(payload)
		return ecdsa.SignASN1(rand.Reader, k, h[:])

	case AlgorithmECDSAP384SHA384:
		k, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%w: ECDSA-P384 requires *ecdsa.PrivateKey, got %T", ErrUnsupportedAlgorithm, key)
		}
		h := sha512.Sum384(payload)
		return ecdsa.SignASN1(rand.Reader, k, h[:])

	case AlgorithmRSAPKCS1v15SHA256:
		k, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%w: RSA-PKCS1v15-SHA256 requires *rsa.PrivateKey, got %T", ErrUnsupportedAlgorithm, key)
		}
		h := sha256.Sum256(payload)
		return rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, h[:])

	case AlgorithmEd25519:
		k, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%w: Ed25519 requires ed25519.PrivateKey, got %T", ErrUnsupportedAlgorithm, key)
		}
		return ed25519.Sign(k, payload), nil

	default:
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedAlgorithm, alg)
	}
}

// verifyWithPub verifies signature over payload using the supplied
// public key under alg. Returns ErrSignatureMismatch when the
// signature does not verify, or ErrUnsupportedAlgorithm if alg or pub
// is unsupported.
func verifyWithPub(pub crypto.PublicKey, alg Algorithm, payload, signature []byte) error {
	switch alg {
	case AlgorithmECDSAP256SHA256:
		p, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: ECDSA-P256 requires *ecdsa.PublicKey, got %T", ErrUnsupportedAlgorithm, pub)
		}
		h := sha256.Sum256(payload)
		if !ecdsa.VerifyASN1(p, h[:], signature) {
			return ErrSignatureMismatch
		}
		return nil

	case AlgorithmECDSAP384SHA384:
		p, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: ECDSA-P384 requires *ecdsa.PublicKey, got %T", ErrUnsupportedAlgorithm, pub)
		}
		h := sha512.Sum384(payload)
		if !ecdsa.VerifyASN1(p, h[:], signature) {
			return ErrSignatureMismatch
		}
		return nil

	case AlgorithmRSAPKCS1v15SHA256:
		p, ok := pub.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: RSA-PKCS1v15-SHA256 requires *rsa.PublicKey, got %T", ErrUnsupportedAlgorithm, pub)
		}
		h := sha256.Sum256(payload)
		if err := rsa.VerifyPKCS1v15(p, crypto.SHA256, h[:], signature); err != nil {
			return fmt.Errorf("%w: %v", ErrSignatureMismatch, err)
		}
		return nil

	case AlgorithmEd25519:
		p, ok := pub.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("%w: Ed25519 requires ed25519.PublicKey, got %T", ErrUnsupportedAlgorithm, pub)
		}
		if !ed25519.Verify(p, payload, signature) {
			return ErrSignatureMismatch
		}
		return nil

	default:
		return fmt.Errorf("%w: %d", ErrUnsupportedAlgorithm, alg)
	}
}
