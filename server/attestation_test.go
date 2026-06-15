package server

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	sharedinternal "github.com/open-telemetry/opamp-go/internal"
	"github.com/open-telemetry/opamp-go/protobufs"
	serverTypes "github.com/open-telemetry/opamp-go/server/types"
	"github.com/open-telemetry/opamp-go/signing"
)

// serverSigningFixture pairs a server-side Signer with a matching
// client-side Verifier so tests can drive a complete round trip
// without re-implementing cert plumbing.
type serverSigningFixture struct {
	signer   signing.Signer
	verifier signing.Verifier
}

func newServerSigningFixture(t *testing.T) serverSigningFixture {
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

	return serverSigningFixture{signer: signer, verifier: verifier}
}

// TestConnectionSigningState_FirstAndSubsequent confirms the envelope
// produced for the first outbound message carries the trust chain
// and a signature; subsequent envelopes carry the signature only.
func TestConnectionSigningState_FirstAndSubsequent(t *testing.T) {
	ctx := context.Background()
	f := newServerSigningFixture(t)

	state, err := newConnectionSigningState(ctx, f.signer)
	require.NoError(t, err)

	first := &protobufs.ServerToAgent{InstanceUid: []byte("first00000000000")}
	env1, err := state.signOutgoing(ctx, first)
	require.NoError(t, err)
	require.NotNil(t, env1.TrustChainResponse, "first envelope MUST carry the chain")
	require.NotEmpty(t, env1.Signature, "server-side signer signs every message including the first")

	// Verify the inner payload round-trips and the signature
	// verifies under the paired verifier.
	leaf, err := f.verifier.ValidateChain(ctx, derChainFromResponse(env1.TrustChainResponse), time.Now())
	require.NoError(t, err)
	require.NoError(t, f.verifier.Verify(ctx, env1.Payload, env1.Signature, leaf))
	var firstInner protobufs.ServerToAgent
	require.NoError(t, proto.Unmarshal(env1.Payload, &firstInner))
	require.Equal(t, first.InstanceUid, firstInner.InstanceUid)

	// Second outbound — no chain.
	second := &protobufs.ServerToAgent{InstanceUid: []byte("second0000000000")}
	env2, err := state.signOutgoing(ctx, second)
	require.NoError(t, err)
	require.Nil(t, env2.TrustChainResponse, "subsequent envelopes do NOT re-send the chain")
	require.NotEmpty(t, env2.Signature)
	require.NoError(t, f.verifier.Verify(ctx, env2.Payload, env2.Signature, leaf))
}

// TestConnectionSigningState_ConcurrentFirstSend confirms that two
// concurrent signOutgoing calls result in exactly one envelope
// carrying the chain (firstSent flag is properly serialised).
func TestConnectionSigningState_ConcurrentFirstSend(t *testing.T) {
	ctx := context.Background()
	f := newServerSigningFixture(t)
	state, err := newConnectionSigningState(ctx, f.signer)
	require.NoError(t, err)

	// Drive two concurrent calls; exactly one should carry the chain.
	type result struct {
		env *protobufs.SignedServerToAgent
		err error
	}
	out := make(chan result, 2)
	for i := 0; i < 2; i++ {
		go func() {
			env, err := state.signOutgoing(ctx, &protobufs.ServerToAgent{InstanceUid: []byte("concurrent000000")})
			out <- result{env: env, err: err}
		}()
	}
	withChain := 0
	withoutChain := 0
	for i := 0; i < 2; i++ {
		r := <-out
		require.NoError(t, r.err)
		if r.env.TrustChainResponse != nil {
			withChain++
		} else {
			withoutChain++
		}
	}
	require.Equal(t, 1, withChain, "exactly one envelope should carry the chain")
	require.Equal(t, 1, withoutChain, "the other envelope should not")
}

// TestConnectionSigningState_NilSigner rejects a nil signer at
// construction.
func TestConnectionSigningState_NilSigner(t *testing.T) {
	_, err := newConnectionSigningState(context.Background(), nil)
	require.Error(t, err)
}

// TestConnectionSigningState_SignerError propagates errors from the
// signer's ChainDER call.
func TestConnectionSigningState_SignerError(t *testing.T) {
	bad := &failingSigner{chainErr: errors.New("chain unavailable")}
	_, err := newConnectionSigningState(context.Background(), bad)
	require.Error(t, err)
}

// TestAgentRequiresAttestation_BitDetection covers the helper that
// inspects AgentToServer.Capabilities for the
// RequiresPayloadTrustVerification bit.
func TestAgentRequiresAttestation_BitDetection(t *testing.T) {
	requiresBit := uint64(protobufs.AgentCapabilities_AgentCapabilities_RequiresPayloadTrustVerification)
	otherBit := uint64(protobufs.AgentCapabilities_AgentCapabilities_ReportsStatus)

	require.False(t, agentRequiresAttestation(0))
	require.False(t, agentRequiresAttestation(otherBit))
	require.True(t, agentRequiresAttestation(requiresBit))
	require.True(t, agentRequiresAttestation(requiresBit|otherBit))
}

// TestAddOffersAttestationBit_Idempotent confirms the helper sets the
// OffersPayloadTrustVerification bit without disturbing other bits.
func TestAddOffersAttestationBit_Idempotent(t *testing.T) {
	offersBit := uint64(protobufs.ServerCapabilities_ServerCapabilities_OffersPayloadTrustVerification)
	otherBit := uint64(protobufs.ServerCapabilities_ServerCapabilities_OffersRemoteConfig)

	require.Equal(t, offersBit, addOffersAttestationBit(0))
	require.Equal(t, offersBit|otherBit, addOffersAttestationBit(otherBit))
	require.Equal(t, offersBit, addOffersAttestationBit(offersBit), "no-op when already set")
}

// derChainFromResponse decodes the PEM blob in TrustChainResponse into
// DER byte slices for the paired verifier's ValidateChain call.
func derChainFromResponse(resp *protobufs.TrustChainResponse) [][]byte {
	var out [][]byte
	rest := resp.CertificateChain
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			out = append(out, block.Bytes)
		}
	}
	return out
}

// failingSigner is a signing.Signer that returns the supplied errors
// from Sign and/or ChainDER. Used to test error-propagation paths.
type failingSigner struct {
	signErr  error
	chainErr error
}

func (s *failingSigner) Sign(_ context.Context, _ []byte) ([]byte, error) {
	if s.signErr != nil {
		return nil, s.signErr
	}
	return []byte("fake-sig"), nil
}

func (s *failingSigner) ChainDER(_ context.Context) ([][]byte, error) {
	if s.chainErr != nil {
		return nil, s.chainErr
	}
	return [][]byte{[]byte("fake-cert")}, nil
}

// TestServerWraps_WhenAgentRequires_WS exercises the WS path
// end-to-end: an Agent declares RequiresPayloadTrustVerification on
// its first AgentToServer; the Server (configured with a
// PayloadSigner) wraps the response in a SignedServerToAgent envelope
// carrying the trust chain and a valid signature. The OffersPayloadTrust
// Verification bit is auto-set on outgoing capabilities.
func TestServerWraps_WhenAgentRequires_WS(t *testing.T) {
	var rcvMsg atomic.Value
	f := newServerSigningFixture(t)

	settings := &StartSettings{Settings: Settings{
		PayloadSigner: f.signer,
		Callbacks: serverTypes.Callbacks{
			OnConnecting: func(_ *http.Request) serverTypes.ConnectionResponse {
				return serverTypes.ConnectionResponse{
					Accept: true,
					ConnectionCallbacks: serverTypes.ConnectionCallbacks{
						OnMessage: func(_ context.Context, _ serverTypes.Connection, message *protobufs.AgentToServer) *protobufs.ServerToAgent {
							rcvMsg.Store(message)
							return &protobufs.ServerToAgent{
								InstanceUid:  message.InstanceUid,
								Capabilities: uint64(protobufs.ServerCapabilities_ServerCapabilities_AcceptsStatus),
							}
						},
					},
				}
			},
		},
	}}

	srv := startServer(t, settings)
	defer srv.Stop(context.Background())

	conn, _, err := dialClient(settings)
	require.NoError(t, err)
	require.NotNil(t, conn)
	defer conn.Close()

	// Send an Agent message that DECLARES the Requires capability —
	// this is what triggers the server-side wrap.
	sendMsg := protobufs.AgentToServer{
		InstanceUid:  testInstanceUid,
		Capabilities: uint64(protobufs.AgentCapabilities_AgentCapabilities_RequiresPayloadTrustVerification),
	}
	bodyBytes, err := proto.Marshal(&sendMsg)
	require.NoError(t, err)
	err = conn.WriteMessage(websocket.BinaryMessage, bodyBytes)
	require.NoError(t, err)

	eventually(t, func() bool { return rcvMsg.Load() != nil })

	mt, frame, err := conn.ReadMessage()
	require.NoError(t, err)
	require.Equal(t, websocket.BinaryMessage, mt)

	// The server's response should be a SignedServerToAgent envelope,
	// NOT a plain ServerToAgent. Decode and verify.
	var envelope protobufs.SignedServerToAgent
	require.NoError(t, sharedinternal.DecodeWSMessage(frame, &envelope))
	require.NotEmpty(t, envelope.Payload, "payload bytes carry the inner ServerToAgent")
	require.NotEmpty(t, envelope.Signature, "first envelope is signed")
	require.NotNil(t, envelope.TrustChainResponse, "first envelope carries the trust chain")
	require.NotEmpty(t, envelope.TrustChainResponse.CertificateChain)

	// Validate the chain against our paired verifier, verify the
	// signature, and confirm the inner payload decodes to the
	// expected ServerToAgent.
	leaf, err := f.verifier.ValidateChain(context.Background(),
		derChainFromResponse(envelope.TrustChainResponse), time.Now())
	require.NoError(t, err)
	require.NoError(t, f.verifier.Verify(context.Background(), envelope.Payload, envelope.Signature, leaf))

	var inner protobufs.ServerToAgent
	require.NoError(t, proto.Unmarshal(envelope.Payload, &inner))
	assert.Equal(t, sendMsg.InstanceUid, inner.InstanceUid)
	// Server auto-set OffersPayloadTrustVerification on the response.
	offersBit := uint64(protobufs.ServerCapabilities_ServerCapabilities_OffersPayloadTrustVerification)
	assert.NotZero(t, inner.Capabilities&offersBit, "OffersPayloadTrustVerification should be auto-set on outgoing capabilities")
}

// TestServerDoesNotWrap_WhenAgentDoesNotRequire_WS confirms that when
// the Agent doesn't set the Requires bit, the Server's outbound
// messages are plain ServerToAgent — NOT wrapped in an envelope —
// even with PayloadSigner configured. The server still advertises
// OffersPayloadTrustVerification in response.Capabilities so the
// Agent learns it could opt in on a future reconnect (per the spec's
// negotiation matrix: No/Yes quadrant — server capable, agent
// declined).
func TestServerDoesNotWrap_WhenAgentDoesNotRequire_WS(t *testing.T) {
	f := newServerSigningFixture(t)

	settings := &StartSettings{Settings: Settings{
		PayloadSigner: f.signer,
		Callbacks: serverTypes.Callbacks{
			OnConnecting: func(_ *http.Request) serverTypes.ConnectionResponse {
				return serverTypes.ConnectionResponse{
					Accept: true,
					ConnectionCallbacks: serverTypes.ConnectionCallbacks{
						OnMessage: func(_ context.Context, _ serverTypes.Connection, message *protobufs.AgentToServer) *protobufs.ServerToAgent {
							return &protobufs.ServerToAgent{InstanceUid: message.InstanceUid}
						},
					},
				}
			},
		},
	}}

	srv := startServer(t, settings)
	defer srv.Stop(context.Background())

	conn, _, err := dialClient(settings)
	require.NoError(t, err)
	defer conn.Close()

	// Agent does NOT set the Requires bit.
	sendMsg := protobufs.AgentToServer{InstanceUid: testInstanceUid}
	bodyBytes, err := proto.Marshal(&sendMsg)
	require.NoError(t, err)
	require.NoError(t, conn.WriteMessage(websocket.BinaryMessage, bodyBytes))

	_, frame, err := conn.ReadMessage()
	require.NoError(t, err)

	// Confirm the response is a plain ServerToAgent (not an
	// envelope). NB: proto3 field-1-as-bytes makes both ServerToAgent
	// and SignedServerToAgent partially decodable from the same wire
	// bytes (InstanceUid vs Payload), so we can't disprove the
	// envelope shape by attempting to decode as one. Instead, decode
	// the wire as ServerToAgent and assert InstanceUid round-trips;
	// then decode as SignedServerToAgent and check the envelope-only
	// fields (Signature field 2, TrustChainResponse field 3) are
	// absent — neither of which exists on ServerToAgent.
	var response protobufs.ServerToAgent
	require.NoError(t, sharedinternal.DecodeWSMessage(frame, &response))
	assert.Equal(t, sendMsg.InstanceUid, response.InstanceUid)
	// Offers bit MUST be advertised because PayloadSigner is
	// configured — spec No/Yes quadrant.
	offersBit := uint64(protobufs.ServerCapabilities_ServerCapabilities_OffersPayloadTrustVerification)
	assert.NotZero(t, response.Capabilities&offersBit,
		"OffersPayloadTrustVerification should be advertised whenever PayloadSigner is configured")

	var envelope protobufs.SignedServerToAgent
	require.NoError(t, sharedinternal.DecodeWSMessage(frame, &envelope))
	require.Empty(t, envelope.Signature, "no signature emitted when Agent didn't opt in")
	require.Nil(t, envelope.TrustChainResponse, "no chain emitted when Agent didn't opt in")
}

// TestSignOutgoing_MidStreamSignFailure_PropagatesError exercises the
// failingSigner.signErr path: a signer that produces a valid chain
// but fails when asked to Sign. signOutgoing must propagate the
// signer's error wrapped with context.
func TestSignOutgoing_MidStreamSignFailure_PropagatesError(t *testing.T) {
	ctx := context.Background()
	signErr := errors.New("e2e test: synthetic signer failure")
	bad := &failingSigner{signErr: signErr}

	state, err := newConnectionSigningState(ctx, bad)
	require.NoError(t, err, "ChainDER should succeed; the failure is on Sign")

	_, err = state.signOutgoing(ctx, &protobufs.ServerToAgent{InstanceUid: testInstanceUid})
	require.Error(t, err)
	require.ErrorIs(t, err, signErr, "signOutgoing should propagate the signer's error")
}
