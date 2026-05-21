package server

import (
	"context"
	"fmt"
	"sync/atomic"

	"google.golang.org/protobuf/proto"

	"github.com/open-telemetry/opamp-go/protobufs"
	"github.com/open-telemetry/opamp-go/signing"
)

// connectionSigningState holds the per-connection state needed to wrap
// outbound ServerToAgent messages in SignedServerToAgent envelopes
// when payload trust verification has been negotiated.
//
// The signer is held by reference; the certificate chain is
// snapshotted at construction time so that operator-side cert
// rotation does not affect a live connection (the agent only
// revalidates the chain on reconnect). firstSent atomically tracks
// whether the chain has already been delivered on this connection so
// that exactly one outbound envelope carries it.
type connectionSigningState struct {
	signer    signing.Signer
	chainDER  [][]byte // snapshot
	firstSent atomic.Bool
}

// newConnectionSigningState constructs the per-connection state by
// asking the signer for its current chain. Errors here propagate to
// the server and prevent the connection from being established with
// signing enabled.
func newConnectionSigningState(ctx context.Context, signer signing.Signer) (*connectionSigningState, error) {
	if signer == nil {
		return nil, fmt.Errorf("server: nil signer")
	}
	chain, err := signer.ChainDER(ctx)
	if err != nil {
		return nil, fmt.Errorf("server: fetch signing chain: %w", err)
	}
	return &connectionSigningState{
		signer:   signer,
		chainDER: chain,
	}, nil
}

// signOutgoing produces a SignedServerToAgent envelope wrapping msg.
// The first call on a given state additionally populates
// trust_chain_response with the snapshotted chain; subsequent calls
// carry only payload + signature.
func (s *connectionSigningState) signOutgoing(ctx context.Context, msg *protobufs.ServerToAgent) (*protobufs.SignedServerToAgent, error) {
	payload, err := proto.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("server: marshal inner ServerToAgent: %w", err)
	}
	sig, err := s.signer.Sign(ctx, payload)
	if err != nil {
		return nil, fmt.Errorf("server: sign payload: %w", err)
	}
	env := &protobufs.SignedServerToAgent{
		Payload:   payload,
		Signature: sig,
	}

	// CompareAndSwap returns true iff we were the goroutine that
	// transitioned firstSent from false to true — guaranteeing exactly
	// one envelope carries the trust chain across concurrent callers.
	if s.firstSent.CompareAndSwap(false, true) {
		chain := make([]*protobufs.TrustChainResponse_Certificate, len(s.chainDER))
		for i, der := range s.chainDER {
			chain[i] = &protobufs.TrustChainResponse_Certificate{DerData: der}
		}
		env.TrustChainResponse = &protobufs.TrustChainResponse{CertificateChain: chain}
	}
	return env, nil
}

// agentRequiresAttestation reports whether the supplied
// AgentToServer.capabilities bitmask requests payload trust
// verification.
func agentRequiresAttestation(capabilities uint64) bool {
	return capabilities&uint64(protobufs.AgentCapabilities_AgentCapabilities_RequiresPayloadTrustVerification) != 0
}

// addOffersAttestationBit returns capabilities with the
// ServerCapabilities_OffersPayloadTrustVerification bit set. It is a
// no-op if the bit is already set.
func addOffersAttestationBit(capabilities uint64) uint64 {
	return capabilities | uint64(protobufs.ServerCapabilities_ServerCapabilities_OffersPayloadTrustVerification)
}
