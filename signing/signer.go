package signing

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"fmt"

	"github.com/open-telemetry/opamp-go/protobufs"
)

// ConfigSigner signs OpAMP remote configurations using ECDSA P-256 + SHA-256.
// It mutates AgentRemoteConfig.Signature and AgentRemoteConfig.SigningCertChain
// in place.
type ConfigSigner struct {
	leafKey      *ecdsa.PrivateKey
	certChainPEM []byte
}

// NewConfigSigner creates a new ConfigSigner from a TLS leaf certificate and
// the PEM-encoded certificate chain (leaf first, then intermediates).
// The TLS certificate must hold an ECDSA P-256 private key.
func NewConfigSigner(leafCert *tls.Certificate, certChainPEM []byte) (*ConfigSigner, error) {
	ecKey, ok := leafCert.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("leaf certificate private key must be ECDSA")
	}
	return &ConfigSigner{
		leafKey:      ecKey,
		certChainPEM: certChainPEM,
	}, nil
}

// SignConfig computes the ECDSA signature for config and stores it in
// config.Signature and config.SigningCertChain. config must not be nil.
func (s *ConfigSigner) SignConfig(config *protobufs.AgentRemoteConfig) error {
	payload, err := configSignedPayload(config)
	if err != nil {
		return fmt.Errorf("cannot compute signed payload: %w", err)
	}

	digest := sha256.Sum256(payload)
	sig, err := signECDSA(s.leafKey, digest[:])
	if err != nil {
		return fmt.Errorf("cannot sign config: %w", err)
	}

	config.Signature = sig
	config.SigningCertChain = s.certChainPEM
	return nil
}

// FileSigner signs OpAMP downloadable file content using ECDSA P-256 + SHA-256.
// It mutates DownloadableFile.Signature and DownloadableFile.SigningCertChain
// in place.
type FileSigner struct {
	leafKey      *ecdsa.PrivateKey
	certChainPEM []byte
}

// NewFileSigner creates a new FileSigner from a TLS leaf certificate and the
// PEM-encoded certificate chain (leaf first, then intermediates).
// The TLS certificate must hold an ECDSA P-256 private key.
func NewFileSigner(leafCert *tls.Certificate, certChainPEM []byte) (*FileSigner, error) {
	ecKey, ok := leafCert.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("leaf certificate private key must be ECDSA")
	}
	return &FileSigner{
		leafKey:      ecKey,
		certChainPEM: certChainPEM,
	}, nil
}

// SignFile computes the ECDSA signature over the raw file content and stores it
// in file.Signature and file.SigningCertChain. file and content must not be nil.
func (s *FileSigner) SignFile(file *protobufs.DownloadableFile, content []byte) error {
	digest := sha256.Sum256(content)
	sig, err := signECDSA(s.leafKey, digest[:])
	if err != nil {
		return fmt.Errorf("cannot sign file: %w", err)
	}

	file.Signature = sig
	file.SigningCertChain = s.certChainPEM
	return nil
}

// signECDSA signs digest with key and returns a DER-encoded ECDSA signature.
func signECDSA(key *ecdsa.PrivateKey, digest []byte) ([]byte, error) {
	return ecdsa.SignASN1(rand.Reader, key, digest)
}
