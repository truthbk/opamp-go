package internal

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/open-telemetry/opamp-go/protobufs"
	"github.com/open-telemetry/opamp-go/signing"
)

// attestationFixture bundles a signer + matching verifier so tests can
// produce wire-realistic SignedServerToAgent envelopes and validate
// them end-to-end without re-implementing the cert plumbing.
type attestationFixture struct {
	signer   *signing.LocalSigner
	verifier *signing.LocalVerifier
	leafCert *x509.Certificate
}

func newAttestationFixture(t *testing.T) attestationFixture {
	t.Helper()
	ca, caKey, err := signing.GenerateCA(signing.AlgorithmECDSAP256SHA256, signing.CertOptions{})
	require.NoError(t, err)
	leaf, leafKey, err := signing.GenerateLeaf(signing.AlgorithmECDSAP256SHA256, ca, caKey, signing.CertOptions{})
	require.NoError(t, err)
	signer, err := signing.NewLocalSigner(leafKey, []*x509.Certificate{leaf})
	require.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AddCert(ca)
	verifier, err := signing.NewLocalVerifier(pool)
	require.NoError(t, err)
	return attestationFixture{signer: signer, verifier: verifier, leafCert: leaf}
}

// buildFirstEnvelope produces the on-the-wire bytes for the FIRST
// SignedServerToAgent on a connection — carries trust_chain_response.
// signFirst controls whether a signature is included; the spec requires
// it on every message, so pass true for happy-path tests and false only
// when testing the missing-signature-on-first-message failure path.
func (f attestationFixture) buildFirstEnvelope(t *testing.T, inner *protobufs.ServerToAgent, signFirst bool) *protobufs.SignedServerToAgent {
	t.Helper()
	payload, err := proto.Marshal(inner)
	require.NoError(t, err)

	chainDER, err := f.signer.ChainDER(context.Background())
	require.NoError(t, err)
	var pemChain []byte
	for _, der := range chainDER {
		pemChain = append(pemChain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}

	env := &protobufs.SignedServerToAgent{
		Payload: payload,
		TrustChainResponse: &protobufs.TrustChainResponse{
			CertificateChain: pemChain,
		},
	}
	if signFirst {
		sig, err := f.signer.Sign(context.Background(), payload)
		require.NoError(t, err)
		env.Signature = sig
	}
	return env
}

// buildSignedEnvelope produces an envelope for a non-first message:
// no trust_chain_response, signature MUST be present.
func (f attestationFixture) buildSignedEnvelope(t *testing.T, inner *protobufs.ServerToAgent) *protobufs.SignedServerToAgent {
	t.Helper()
	payload, err := proto.Marshal(inner)
	require.NoError(t, err)
	sig, err := f.signer.Sign(context.Background(), payload)
	require.NoError(t, err)
	return &protobufs.SignedServerToAgent{Payload: payload, Signature: sig}
}

// TestAttestationState_FirstAndSubsequent exercises the happy path
// through both the handshake (first envelope) and the per-message
// signature verification (subsequent envelopes).
func TestAttestationState_FirstAndSubsequent(t *testing.T) {
	f := newAttestationFixture(t)
	state := newAttestationState(f.verifier)
	ctx := context.Background()

	first := &protobufs.ServerToAgent{InstanceUid: []byte("first-msg-uid000")}
	firstEnv := f.buildFirstEnvelope(t, first, true /* signFirst — mandatory per spec */)

	payload, err := state.ProcessEnvelope(ctx, firstEnv)
	require.NoError(t, err)
	var firstParsed protobufs.ServerToAgent
	require.NoError(t, proto.Unmarshal(payload, &firstParsed))
	require.Equal(t, first.InstanceUid, firstParsed.InstanceUid)

	// State should now have a leaf cached.
	require.NotNil(t, state.leaf)
	require.True(t, state.firstSeen)

	// Subsequent message: must include a signature.
	second := &protobufs.ServerToAgent{InstanceUid: []byte("second-msg-uid00")}
	secondEnv := f.buildSignedEnvelope(t, second)

	payload, err = state.ProcessEnvelope(ctx, secondEnv)
	require.NoError(t, err)
	var secondParsed protobufs.ServerToAgent
	require.NoError(t, proto.Unmarshal(payload, &secondParsed))
	require.Equal(t, second.InstanceUid, secondParsed.InstanceUid)
}

// TestAttestationState_FirstMessageMustBeSigned confirms that the first
// envelope's signature is verified against the freshly validated leaf.
func TestAttestationState_FirstMessageMustBeSigned(t *testing.T) {
	f := newAttestationFixture(t)
	state := newAttestationState(f.verifier)
	ctx := context.Background()

	inner := &protobufs.ServerToAgent{InstanceUid: []byte("signed-first-uid")}
	env := f.buildFirstEnvelope(t, inner, true)

	_, err := state.ProcessEnvelope(ctx, env)
	require.NoError(t, err)
}

// TestAttestationState_MissingSignatureOnFirst confirms that the first
// message is rejected when its signature is absent.
func TestAttestationState_MissingSignatureOnFirst(t *testing.T) {
	f := newAttestationFixture(t)
	state := newAttestationState(f.verifier)
	ctx := context.Background()

	inner := &protobufs.ServerToAgent{InstanceUid: []byte("no-sig-first-uid")}
	env := f.buildFirstEnvelope(t, inner, false /* no signature */)

	_, err := state.ProcessEnvelope(ctx, env)
	require.ErrorIs(t, err, ErrMissingSignature)
}

// TestAttestationState_FirstMessageSignedButTampered confirms that
// when the first message carries a signature but it's invalid, the
// state rejects it.
func TestAttestationState_FirstMessageSignedButTampered(t *testing.T) {
	f := newAttestationFixture(t)
	state := newAttestationState(f.verifier)
	ctx := context.Background()

	inner := &protobufs.ServerToAgent{InstanceUid: []byte("tampered-first0")}
	env := f.buildFirstEnvelope(t, inner, true)
	env.Signature[0] ^= 0xff

	_, err := state.ProcessEnvelope(ctx, env)
	require.Error(t, err)
	require.ErrorIs(t, err, signing.ErrSignatureMismatch)
}

// TestAttestationState_MissingTrustChain confirms ErrMissingTrustChain
// when the first envelope lacks trust_chain_response.
func TestAttestationState_MissingTrustChain(t *testing.T) {
	f := newAttestationFixture(t)
	state := newAttestationState(f.verifier)
	ctx := context.Background()

	inner := &protobufs.ServerToAgent{InstanceUid: []byte("no-chain-uid000")}
	payload, err := proto.Marshal(inner)
	require.NoError(t, err)
	env := &protobufs.SignedServerToAgent{Payload: payload}

	_, err = state.ProcessEnvelope(ctx, env)
	require.ErrorIs(t, err, ErrMissingTrustChain)
}

// TestAttestationState_TrustChainErrorReported confirms that a
// non-empty error_message on the first envelope produces
// ErrTrustChainErrorReported.
func TestAttestationState_TrustChainErrorReported(t *testing.T) {
	f := newAttestationFixture(t)
	state := newAttestationState(f.verifier)
	ctx := context.Background()

	inner := &protobufs.ServerToAgent{InstanceUid: []byte("err-msg-uid00000")}
	payload, err := proto.Marshal(inner)
	require.NoError(t, err)
	env := &protobufs.SignedServerToAgent{
		Payload: payload,
		TrustChainResponse: &protobufs.TrustChainResponse{
			ErrorMessage: "server cannot sign right now",
		},
	}

	_, err = state.ProcessEnvelope(ctx, env)
	require.ErrorIs(t, err, ErrTrustChainErrorReported)
}

// TestAttestationState_UnknownCA confirms an envelope whose chain
// does not validate against the verifier's trust pool is rejected.
func TestAttestationState_UnknownCA(t *testing.T) {
	f := newAttestationFixture(t)
	// Build a SECOND fixture with a different CA — its envelope won't
	// validate against f.verifier.
	other := newAttestationFixture(t)
	state := newAttestationState(f.verifier)
	ctx := context.Background()

	inner := &protobufs.ServerToAgent{InstanceUid: []byte("unknown-ca-uid00")}
	env := other.buildFirstEnvelope(t, inner, false)

	_, err := state.ProcessEnvelope(ctx, env)
	require.Error(t, err)
	require.ErrorIs(t, err, signing.ErrChainValidation)
}

// TestAttestationState_MissingSignatureOnSubsequent confirms that
// after a successful handshake, an envelope without a signature is
// rejected.
func TestAttestationState_MissingSignatureOnSubsequent(t *testing.T) {
	f := newAttestationFixture(t)
	state := newAttestationState(f.verifier)
	ctx := context.Background()

	first := &protobufs.ServerToAgent{InstanceUid: []byte("first00000000000")}
	_, err := state.ProcessEnvelope(ctx, f.buildFirstEnvelope(t, first, true))
	require.NoError(t, err)

	second := &protobufs.ServerToAgent{InstanceUid: []byte("second0000000000")}
	payload, err := proto.Marshal(second)
	require.NoError(t, err)
	env := &protobufs.SignedServerToAgent{Payload: payload} // no signature

	_, err = state.ProcessEnvelope(ctx, env)
	require.ErrorIs(t, err, ErrMissingSignature)
}

// TestAttestationState_TamperedSignatureOnSubsequent confirms that a
// flipped byte in the signature is rejected.
func TestAttestationState_TamperedSignatureOnSubsequent(t *testing.T) {
	f := newAttestationFixture(t)
	state := newAttestationState(f.verifier)
	ctx := context.Background()

	first := &protobufs.ServerToAgent{InstanceUid: []byte("first00000000000")}
	_, err := state.ProcessEnvelope(ctx, f.buildFirstEnvelope(t, first, true))
	require.NoError(t, err)

	second := &protobufs.ServerToAgent{InstanceUid: []byte("second0000000000")}
	env := f.buildSignedEnvelope(t, second)
	env.Signature[len(env.Signature)-1] ^= 0xff

	_, err = state.ProcessEnvelope(ctx, env)
	require.ErrorIs(t, err, signing.ErrSignatureMismatch)
}

// TestAttestationState_EmptyPayload confirms an envelope with no
// payload bytes is rejected up front — an empty inner ServerToAgent
// would unmarshal to a no-op, which is not a useful message and may
// hide signaling issues.
func TestAttestationState_EmptyPayload(t *testing.T) {
	f := newAttestationFixture(t)
	state := newAttestationState(f.verifier)
	ctx := context.Background()

	env := &protobufs.SignedServerToAgent{}
	_, err := state.ProcessEnvelope(ctx, env)
	require.ErrorIs(t, err, ErrMissingPayload)
}

// TestUnwrapServerToAgent_NilState_PassThrough confirms that when no
// attestation state is configured, unwrapServerToAgent acts as a
// plain proto.Unmarshal of the wire bytes into a ServerToAgent.
func TestUnwrapServerToAgent_NilState_PassThrough(t *testing.T) {
	inner := &protobufs.ServerToAgent{InstanceUid: []byte("plain-uid0000000")}
	bytes, err := proto.Marshal(inner)
	require.NoError(t, err)

	var msg protobufs.ServerToAgent
	require.NoError(t, unwrapServerToAgent(context.Background(), nil, bytes, &msg))
	require.Equal(t, inner.InstanceUid, msg.InstanceUid)
}

// TestUnwrapServerToAgent_WithState_HappyPath confirms that with an
// attestation state, wire bytes are unmarshalled as a
// SignedServerToAgent envelope and the inner ServerToAgent is
// returned.
func TestUnwrapServerToAgent_WithState_HappyPath(t *testing.T) {
	f := newAttestationFixture(t)
	state := newAttestationState(f.verifier)

	inner := &protobufs.ServerToAgent{InstanceUid: []byte("envelope-uid0000")}
	env := f.buildFirstEnvelope(t, inner, true)
	envBytes, err := proto.Marshal(env)
	require.NoError(t, err)

	var msg protobufs.ServerToAgent
	require.NoError(t, unwrapServerToAgent(context.Background(), state, envBytes, &msg))
	require.Equal(t, inner.InstanceUid, msg.InstanceUid)
}

// TestUnwrapServerToAgent_WithState_GarbageBytes confirms that
// non-SignedServerToAgent bytes returned over the wire when signing
// is negotiated are rejected.
func TestUnwrapServerToAgent_WithState_GarbageBytes(t *testing.T) {
	f := newAttestationFixture(t)
	state := newAttestationState(f.verifier)

	var msg protobufs.ServerToAgent
	// Bytes that don't decode as SignedServerToAgent — proto3 is
	// forgiving but completely random bytes typically still fail.
	err := unwrapServerToAgent(context.Background(), state, []byte{0xff, 0xfe, 0xfd, 0xfc}, &msg)
	require.Error(t, err)
}

// TestAttestationState_Reset confirms that Reset() returns the state
// to its initial (handshake-pending) form. The use case is the HTTP
// polling transport, which lacks a persistent connection to drop on
// attestation failure and must be able to re-handshake on the next
// poll.
func TestAttestationState_Reset(t *testing.T) {
	f := newAttestationFixture(t)
	state := newAttestationState(f.verifier)
	ctx := context.Background()

	// Drive the state through a successful handshake.
	first := &protobufs.ServerToAgent{InstanceUid: []byte("first00000000000")}
	_, err := state.ProcessEnvelope(ctx, f.buildFirstEnvelope(t, first, true))
	require.NoError(t, err)
	require.True(t, state.firstSeen)
	require.NotNil(t, state.leaf)

	// Reset and confirm the state is handshake-pending again.
	state.Reset()
	require.False(t, state.firstSeen)
	require.Nil(t, state.leaf)

	// A "next" envelope without trust_chain_response now produces
	// ErrMissingTrustChain (rather than ErrMissingSignature), proving
	// the state is back to first-message semantics.
	second := &protobufs.ServerToAgent{InstanceUid: []byte("second0000000000")}
	envWithoutChain := f.buildSignedEnvelope(t, second)
	envWithoutChain.TrustChainResponse = nil

	_, err = state.ProcessEnvelope(ctx, envWithoutChain)
	require.ErrorIs(t, err, ErrMissingTrustChain)

	// A fresh first-message envelope succeeds after Reset.
	thirdEnv := f.buildFirstEnvelope(t, second, true)
	_, err = state.ProcessEnvelope(ctx, thirdEnv)
	require.NoError(t, err)
}

// TestIsAttestationFailure_ClassifiesSentinels confirms the
// classification helper used by the WS receive loop to decide when to
// close the connection.
func TestIsAttestationFailure_ClassifiesSentinels(t *testing.T) {
	require.False(t, isAttestationFailure(nil))

	// Local attestation sentinels.
	require.True(t, isAttestationFailure(ErrMissingTrustChain))
	require.True(t, isAttestationFailure(ErrTrustChainErrorReported))
	require.True(t, isAttestationFailure(ErrMissingSignature))
	require.True(t, isAttestationFailure(ErrMissingPayload))

	// Signing-package sentinels propagated up.
	require.True(t, isAttestationFailure(signing.ErrChainValidation))
	require.True(t, isAttestationFailure(signing.ErrSignatureMismatch))
	require.True(t, isAttestationFailure(signing.ErrEmptyChain))
	require.True(t, isAttestationFailure(signing.ErrParseCertificate))
	require.True(t, isAttestationFailure(signing.ErrUnsupportedAlgorithm))

	// Wrapped errors still classify correctly (errors.Is chain).
	wrapped := fmt.Errorf("client: validate trust chain: %w", signing.ErrChainValidation)
	require.True(t, isAttestationFailure(wrapped))

	// Generic transport errors do NOT classify as attestation failures.
	require.False(t, isAttestationFailure(errors.New("read: connection reset")))
}
