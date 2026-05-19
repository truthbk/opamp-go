package signing

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
)

// ErrNilKey is returned by NewLocalSigner when key is nil.
var ErrNilKey = errors.New("signing: nil private key")

// LocalSigner is the in-process reference implementation of [Signer].
// It holds a private key and certificate chain in memory and signs
// requests synchronously without any network IO.
//
// LocalSigner is suitable for tests, the opamp-go example server, and
// any deployment where the signing private key is colocated with the
// OpAMP server process. Deployments that delegate signing to a hosted
// platform (HSM-backed RPC, central signing service) should provide
// their own Signer implementation; the wire-level opamp-go code is
// agnostic to which Signer is in use.
//
// LocalSigner is safe for concurrent use: the underlying crypto.Signer
// implementations in the Go standard library are themselves
// concurrency-safe.
type LocalSigner struct {
	key      crypto.Signer
	alg      Algorithm
	chainDER [][]byte
}

// NewLocalSigner constructs a LocalSigner from the supplied private
// key (typically a crypto.Signer implementation from the standard
// library) and certificate chain.
//
// The chain MUST be ordered intermediates first, leaf last; the leaf
// is the certificate whose private key signs payloads. The root MUST
// NOT be included — the Agent supplies the root via its pre-configured
// trust anchor pool.
//
// The algorithm is determined by the leaf certificate's
// SignatureAlgorithm; ErrUnsupportedAlgorithm is returned for any
// value outside the supported baseline.
func NewLocalSigner(key crypto.Signer, chain []*x509.Certificate) (*LocalSigner, error) {
	if key == nil {
		return nil, ErrNilKey
	}
	if len(chain) == 0 {
		return nil, ErrEmptyChain
	}
	leaf := chain[len(chain)-1]
	alg, err := algorithmFromCert(leaf)
	if err != nil {
		return nil, err
	}

	chainDER := make([][]byte, len(chain))
	for i, cert := range chain {
		// cert.Raw is the DER bytes the certificate was parsed from
		// (or that x509.CreateCertificate produced). Copy to defend
		// against later mutation of cert.Raw by callers, even though
		// it's expected to be immutable in practice.
		raw := make([]byte, len(cert.Raw))
		copy(raw, cert.Raw)
		chainDER[i] = raw
	}

	return &LocalSigner{
		key:      key,
		alg:      alg,
		chainDER: chainDER,
	}, nil
}

// Sign implements [Signer]. The context is honoured only for
// cancellation; the in-process signing operation itself does not block.
func (s *LocalSigner) Sign(ctx context.Context, payload []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return signWithKey(s.key, s.alg, payload)
}

// ChainDER implements [Signer]. Returns a defensive copy so callers
// cannot mutate the signer's internal state.
func (s *LocalSigner) ChainDER(ctx context.Context) ([][]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	out := make([][]byte, len(s.chainDER))
	for i, der := range s.chainDER {
		clone := make([]byte, len(der))
		copy(clone, der)
		out[i] = clone
	}
	return out, nil
}

// Algorithm reports the algorithm dispatched by this signer (derived
// from the leaf certificate). Exposed for diagnostics and tests.
func (s *LocalSigner) Algorithm() Algorithm {
	return s.alg
}
