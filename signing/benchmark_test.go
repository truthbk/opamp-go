package signing

import (
	"context"
	"crypto/x509"
	"testing"
)

// benchPayload approximates the size of a typical ServerToAgent —
// not so small that fixed costs dominate, not so large that the
// hash function (rather than the asymmetric op) becomes the bottleneck.
// 1 KiB is roughly an OpAMP RemoteConfig with a handful of receivers.
var benchPayload = func() []byte {
	b := make([]byte, 1024)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}()

// BenchmarkSign reports the per-message Sign cost for each supported
// algorithm. Useful for operators sizing OpAMP servers: at 10⁶ agents
// each receiving a heartbeat every 30s, the server's signing budget
// is ~33k ops/s — these numbers tell you whether that fits one CPU
// core.
//
// Run with:
//
//	go test -bench=BenchmarkSign -benchmem ./signing/
func BenchmarkSign(b *testing.B) {
	for _, alg := range allAlgorithms {
		b.Run(alg.String(), func(b *testing.B) {
			_, signer, _ := benchKeyPair(b, alg)
			ctx := context.Background()
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := signer.Sign(ctx, benchPayload); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkVerify reports the per-message Verify cost for each
// supported algorithm. This is the agent's per-envelope overhead in
// steady state (chain validation runs only on the first envelope of
// each connection).
func BenchmarkVerify(b *testing.B) {
	for _, alg := range allAlgorithms {
		b.Run(alg.String(), func(b *testing.B) {
			leaf, signer, verifier := benchKeyPair(b, alg)
			ctx := context.Background()
			sig, err := signer.Sign(ctx, benchPayload)
			if err != nil {
				b.Fatal(err)
			}
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if err := verifier.Verify(ctx, benchPayload, sig, leaf); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// benchKeyPair mirrors testKeyPair but takes *testing.B. Kept separate
// to avoid coupling benchmark setup to test-only assertions.
func benchKeyPair(b *testing.B, alg Algorithm) (*x509.Certificate, *LocalSigner, *LocalVerifier) {
	b.Helper()
	ca, caKey, err := GenerateCA(alg, CertOptions{})
	if err != nil {
		b.Fatal(err)
	}
	leaf, leafKey, err := GenerateLeaf(alg, ca, caKey, CertOptions{})
	if err != nil {
		b.Fatal(err)
	}
	signer, err := NewLocalSigner(leafKey, []*x509.Certificate{leaf})
	if err != nil {
		b.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	verifier, err := NewLocalVerifier(roots)
	if err != nil {
		b.Fatal(err)
	}
	return leaf, signer, verifier
}
