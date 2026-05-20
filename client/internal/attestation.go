package internal

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/open-telemetry/opamp-go/protobufs"
	"github.com/open-telemetry/opamp-go/signing"
)

// Sentinel errors returned by attestationState. Callers can use
// errors.Is to distinguish failure modes when terminating the
// connection.
var (
	// ErrMissingTrustChain is returned when the first
	// SignedServerToAgent received on a connection does not carry a
	// trust_chain_response field. Per the spec this is a fatal
	// handshake error.
	ErrMissingTrustChain = errors.New("client: first SignedServerToAgent missing trust_chain_response")

	// ErrTrustChainErrorReported is returned when the Server populates
	// trust_chain_response.error_message, signalling that it cannot
	// satisfy the handshake.
	ErrTrustChainErrorReported = errors.New("client: server reported trust chain error")

	// ErrMissingSignature is returned when a SignedServerToAgent after
	// the first is missing its signature field. Subsequent messages
	// MUST be signed.
	ErrMissingSignature = errors.New("client: SignedServerToAgent missing signature on non-first message")

	// ErrMissingPayload is returned when SignedServerToAgent.payload
	// is empty. The payload carries the inner ServerToAgent; an empty
	// payload would unmarshal into an empty ServerToAgent and is
	// rejected eagerly.
	ErrMissingPayload = errors.New("client: SignedServerToAgent missing payload")
)

// attestationState holds per-connection state for payload trust
// verification on the Agent (client) side. Construct one per OpAMP
// connection via newAttestationState and call ProcessEnvelope on each
// inbound SignedServerToAgent.
//
// When Verifier is nil (the operator did not opt in), the OpAMP wire
// format is byte-identical to upstream and no attestationState is
// created at all; payload trust is simply not negotiated.
type attestationState struct {
	verifier signing.Verifier

	mu        sync.Mutex
	firstSeen bool
	leaf      *x509.Certificate
}

// newAttestationState constructs a per-connection attestation state.
// verifier MUST be non-nil; callers without a configured verifier
// should not construct an attestationState at all.
func newAttestationState(verifier signing.Verifier) *attestationState {
	return &attestationState{verifier: verifier}
}

// ProcessEnvelope handles an incoming SignedServerToAgent received on
// this connection. On the first call, the envelope's certificate
// chain is validated against the verifier's pre-configured trust
// anchor pool and the resulting leaf is cached on the state. On
// subsequent calls, the envelope's signature is verified against the
// cached leaf.
//
// On success it returns the inner ServerToAgent payload bytes, which
// the caller unmarshals into a *protobufs.ServerToAgent for normal
// dispatch.
//
// On any failure — missing trust chain, chain validation failure,
// missing/invalid signature — it returns a non-nil error. Per the
// spec the caller MUST then terminate the OpAMP connection.
func (s *attestationState) ProcessEnvelope(ctx context.Context, envelope *protobufs.SignedServerToAgent) ([]byte, error) {
	if envelope == nil {
		return nil, errors.New("client: nil SignedServerToAgent envelope")
	}
	if len(envelope.Payload) == 0 {
		return nil, ErrMissingPayload
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.firstSeen {
		chainResp := envelope.TrustChainResponse
		if chainResp == nil {
			return nil, ErrMissingTrustChain
		}
		if chainResp.ErrorMessage != "" {
			return nil, fmt.Errorf("%w: %s", ErrTrustChainErrorReported, chainResp.ErrorMessage)
		}
		chainDER := make([][]byte, len(chainResp.CertificateChain))
		for i, cert := range chainResp.CertificateChain {
			chainDER[i] = cert.GetDerData()
		}
		leaf, err := s.verifier.ValidateChain(ctx, chainDER, time.Now())
		if err != nil {
			return nil, fmt.Errorf("client: validate trust chain: %w", err)
		}
		s.leaf = leaf
		s.firstSeen = true

		// First message MAY be unsigned per the spec (chain validation
		// establishes trust at this point). If a signature is present,
		// verify it as defence in depth — a server that supplies a
		// signature alongside the chain handshake should produce a
		// valid one.
		if len(envelope.Signature) > 0 {
			if err := s.verifier.Verify(ctx, envelope.Payload, envelope.Signature, leaf); err != nil {
				return nil, fmt.Errorf("client: verify first message signature: %w", err)
			}
		}
		return envelope.Payload, nil
	}

	// Subsequent messages: signature MUST be present and verifiable.
	if len(envelope.Signature) == 0 {
		return nil, ErrMissingSignature
	}
	if err := s.verifier.Verify(ctx, envelope.Payload, envelope.Signature, s.leaf); err != nil {
		return nil, fmt.Errorf("client: verify signature: %w", err)
	}
	return envelope.Payload, nil
}

// unwrapServerToAgent is a convenience that combines ProcessEnvelope
// with proto.Unmarshal of the resulting payload bytes into msg. If
// state is nil, the input bytes are unmarshalled directly as a
// ServerToAgent (the standard non-attestation path).
//
// rawProto is the protobuf bytes after any transport-level framing
// has been stripped (for WebSocket, after the wsMsgHeader varint).
func unwrapServerToAgent(ctx context.Context, state *attestationState, rawProto []byte, msg *protobufs.ServerToAgent) error {
	if state == nil {
		return proto.Unmarshal(rawProto, msg)
	}
	var envelope protobufs.SignedServerToAgent
	if err := proto.Unmarshal(rawProto, &envelope); err != nil {
		return fmt.Errorf("client: decode SignedServerToAgent envelope: %w", err)
	}
	payload, err := state.ProcessEnvelope(ctx, &envelope)
	if err != nil {
		return err
	}
	if err := proto.Unmarshal(payload, msg); err != nil {
		return fmt.Errorf("client: decode inner ServerToAgent: %w", err)
	}
	return nil
}
