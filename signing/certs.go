// Package signing provides X.509 signing and verification for OpAMP remote
// configurations and package files using ECDSA P-256 + SHA-256.
package signing

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// GenerateECDSACA generates a new ECDSA P-256 CA certificate and key pair.
// Returns the private key, the parsed certificate, the PEM-encoded certificate
// bytes, and an error.
func GenerateECDSACA() (*ecdsa.PrivateKey, *x509.Certificate, []byte, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("cannot generate CA key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("cannot generate serial number: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "OpAMP Signing CA",
			Organization: []string{"OpAMP"},
		},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("cannot create CA certificate: %w", err)
	}

	caCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("cannot parse CA certificate: %w", err)
	}

	pemBuf := new(bytes.Buffer)
	if err := pem.Encode(pemBuf, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return nil, nil, nil, fmt.Errorf("cannot PEM-encode CA certificate: %w", err)
	}

	return caKey, caCert, pemBuf.Bytes(), nil
}

// GenerateECDSALeafCert generates a new ECDSA P-256 leaf certificate signed by
// the provided CA. The leaf certificate has ExtKeyUsageCodeSigning.
// Returns the tls.Certificate (for use with signers), the PEM bundle (leaf cert
// only, suitable as signing_cert_chain), and an error.
func GenerateECDSALeafCert(ca *x509.Certificate, caKey *ecdsa.PrivateKey) (*tls.Certificate, []byte, error) {
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot generate leaf key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("cannot generate serial number: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "OpAMP Signing Leaf",
			Organization: []string{"OpAMP"},
		},
		NotBefore:   time.Now().Add(-time.Minute),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot create leaf certificate: %w", err)
	}

	certPEMBuf := new(bytes.Buffer)
	if err := pem.Encode(certPEMBuf, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return nil, nil, fmt.Errorf("cannot PEM-encode leaf certificate: %w", err)
	}

	leafKeyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot marshal leaf key: %w", err)
	}
	keyPEMBuf := new(bytes.Buffer)
	if err := pem.Encode(keyPEMBuf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: leafKeyDER}); err != nil {
		return nil, nil, fmt.Errorf("cannot PEM-encode leaf key: %w", err)
	}

	tlsCert, err := tls.X509KeyPair(certPEMBuf.Bytes(), keyPEMBuf.Bytes())
	if err != nil {
		return nil, nil, fmt.Errorf("cannot create tls.Certificate: %w", err)
	}

	return &tlsCert, certPEMBuf.Bytes(), nil
}
