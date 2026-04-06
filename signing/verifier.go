package signing

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/open-telemetry/opamp-go/protobufs"
)

// ErrMissingSignature is returned when the signature or signing cert chain is absent
// but the verifier requires them.
var ErrMissingSignature = errors.New("missing signature or signing_cert_chain")

// SignatureVerifier verifies X.509 signatures on OpAMP remote configs and
// package files.
type SignatureVerifier interface {
	// VerifyRemoteConfig verifies the X.509 signature on a remote config.
	// Returns nil if the signature is valid, or an error describing why it failed.
	VerifyRemoteConfig(config *protobufs.AgentRemoteConfig) error

	// VerifyFile verifies the X.509 signature on a downloadable file against
	// the provided raw content bytes.
	// Returns nil if the signature is valid, or an error describing why it failed.
	VerifyFile(file *protobufs.DownloadableFile, content []byte) error
}

// X509SignatureVerifier verifies ECDSA P-256 + SHA-256 signatures using a
// configured pool of trust anchors (CA certificates).
type X509SignatureVerifier struct {
	trustAnchors *x509.CertPool
}

// NewX509SignatureVerifier creates a new verifier using the provided cert pool
// as the set of trusted CA certificates. trustAnchors must not be nil.
func NewX509SignatureVerifier(trustAnchors *x509.CertPool) *X509SignatureVerifier {
	return &X509SignatureVerifier{trustAnchors: trustAnchors}
}

// VerifyRemoteConfig verifies the signature on a remote config.
// The signed bytes are: deterministic proto marshal of config.Config concatenated
// with config.ConfigHash. The signature must be a DER-encoded ECDSA signature
// produced by the leaf key in config.SigningCertChain.
func (v *X509SignatureVerifier) VerifyRemoteConfig(config *protobufs.AgentRemoteConfig) error {
	if len(config.GetSignature()) == 0 || len(config.GetSigningCertChain()) == 0 {
		return ErrMissingSignature
	}

	leafCert, err := v.verifyCertChain(config.GetSigningCertChain())
	if err != nil {
		return fmt.Errorf("certificate chain verification failed: %w", err)
	}

	payload, err := configSignedPayload(config)
	if err != nil {
		return fmt.Errorf("cannot compute signed payload: %w", err)
	}

	digest := sha256.Sum256(payload)
	if err := verifyECDSA(leafCert, digest[:], config.GetSignature()); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}

// VerifyFile verifies the signature on a downloadable file against raw content bytes.
// The signed bytes are the raw file content. The signature must be a DER-encoded
// ECDSA signature produced by the leaf key in file.SigningCertChain.
func (v *X509SignatureVerifier) VerifyFile(file *protobufs.DownloadableFile, content []byte) error {
	if len(file.GetSignature()) == 0 || len(file.GetSigningCertChain()) == 0 {
		return ErrMissingSignature
	}

	leafCert, err := v.verifyCertChain(file.GetSigningCertChain())
	if err != nil {
		return fmt.Errorf("certificate chain verification failed: %w", err)
	}

	digest := sha256.Sum256(content)
	if err := verifyECDSA(leafCert, digest[:], file.GetSignature()); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}

// verifyCertChain parses the PEM bundle, builds the chain, validates it against
// the trust anchors, and returns the leaf certificate.
func (v *X509SignatureVerifier) verifyCertChain(pemBundle []byte) (*x509.Certificate, error) {
	certs, err := parsePEMCerts(pemBundle)
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, errors.New("signing_cert_chain is empty")
	}

	leaf := certs[0]

	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}

	opts := x509.VerifyOptions{
		Roots:         v.trustAnchors,
		Intermediates: intermediates,
		CurrentTime:   time.Now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}

	if _, err := leaf.Verify(opts); err != nil {
		return nil, err
	}

	return leaf, nil
}

// configSignedPayload returns the bytes to be signed for a remote config.
// Format: 4-byte big-endian length of configBytes || configBytes || ConfigHash.
// The length prefix unambiguously delimits the two fields, preventing a
// length-confusion attack where distinct (Config, Hash) pairs produce the same bytes.
func configSignedPayload(config *protobufs.AgentRemoteConfig) ([]byte, error) {
	var configBytes []byte
	if config.GetConfig() != nil {
		var err error
		configBytes, err = proto.MarshalOptions{Deterministic: true}.Marshal(config.GetConfig())
		if err != nil {
			return nil, fmt.Errorf("cannot marshal config: %w", err)
		}
	}
	// Guard against silent uint32 truncation on hypothetical 64-bit builds
	// where a pathologically large proto marshal could exceed 4 GiB. In practice
	// this is unreachable (proto.Marshal would OOM first), but the check is
	// cheap and makes the cast auditable.
	if len(configBytes) > math.MaxUint32 {
		return nil, fmt.Errorf("config marshal too large (%d bytes) for 4-byte length prefix", len(configBytes))
	}
	payload := make([]byte, 4+len(configBytes)+len(config.GetConfigHash()))
	binary.BigEndian.PutUint32(payload[:4], uint32(len(configBytes)))
	copy(payload[4:], configBytes)
	copy(payload[4+len(configBytes):], config.GetConfigHash())
	return payload, nil
}

// maxCertChainLen is the maximum number of certificates accepted in a
// signing_cert_chain PEM bundle. This limits CPU and memory usage when
// processing server-supplied cert chains.
const maxCertChainLen = 10

// parsePEMCerts parses all CERTIFICATE PEM blocks from the given bundle.
// Returns an error if the bundle contains more than maxCertChainLen certificates.
func parsePEMCerts(pemBundle []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := pemBundle
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		if len(certs) >= maxCertChainLen {
			return nil, fmt.Errorf("signing_cert_chain exceeds maximum allowed length of %d certificates", maxCertChainLen)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("cannot parse certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// verifyECDSA verifies a DER-encoded ECDSA signature over digest using the
// leaf certificate's public key. Uses ecdsa.VerifyASN1 which correctly rejects
// signatures with trailing bytes.
func verifyECDSA(leaf *x509.Certificate, digest, sig []byte) error {
	ecKey, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("leaf certificate public key is not ECDSA")
	}
	if !ecdsa.VerifyASN1(ecKey, digest, sig) {
		return errors.New("ECDSA signature mismatch")
	}
	return nil
}
