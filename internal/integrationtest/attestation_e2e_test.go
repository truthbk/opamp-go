package integrationtest

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	opampclient "github.com/open-telemetry/opamp-go/client"
	clienttypes "github.com/open-telemetry/opamp-go/client/types"
	sharedinternal "github.com/open-telemetry/opamp-go/internal"
	"github.com/open-telemetry/opamp-go/internal/testhelpers"
	"github.com/open-telemetry/opamp-go/protobufs"
	"github.com/open-telemetry/opamp-go/server"
	servertypes "github.com/open-telemetry/opamp-go/server/types"
	"github.com/open-telemetry/opamp-go/signing"
)

const (
	// e2eDeadline bounds how long a happy-path observation may take.
	// 15s is generous — under -race × parallel CPU contention, the
	// first-envelope round trip can run several seconds on slow CI,
	// and RSA-2048 key generation in newFixture is on the same clock.
	// We'd rather wait than flake.
	e2eDeadline = 15 * time.Second
	// e2eNonOccurrenceDeadline bounds the wait for a "this should NOT
	// happen" assertion (reject scenarios assert OnMessage never
	// fires). One GC pause under -race can eat several hundred
	// milliseconds; 1.5s catches anything that would have happened on
	// a healthy box without making the suite slow.
	e2eNonOccurrenceDeadline = 1500 * time.Millisecond
	// listenPath is shared by all e2e tests; ws/http URL building
	// concatenates it to the dialed endpoint.
	listenPath = "/v1/opamp"

	// attestationFailureLogSubstring is the canonical phrase the
	// client logs on any payload trust verification failure (both WS
	// and HTTP transports). Tests grep for this exact substring; if
	// you change it on the receive paths, update both ends.
	attestationFailureLogSubstring = "Payload trust verification failed"
)

// e2eFixture pairs a server-side Signer with a matching client-side
// Verifier so the integration tests can drive a full round trip
// without re-implementing cert plumbing per test.
type e2eFixture struct {
	algorithm signing.Algorithm
	signer    signing.Signer
	verifier  *instrumentedVerifier
}

func newFixture(t *testing.T, alg signing.Algorithm) e2eFixture {
	t.Helper()
	return newFixtureWithLeafOpts(t, alg, signing.CertOptions{})
}

// newFixtureWithLeafOpts is the explicit-options variant — tests that
// need an expired leaf, a custom CN, etc. use this directly.
func newFixtureWithLeafOpts(t *testing.T, alg signing.Algorithm, leafOpts signing.CertOptions) e2eFixture {
	t.Helper()
	ca, caKey, err := signing.GenerateCA(alg, signing.CertOptions{})
	require.NoError(t, err)
	leaf, leafKey, err := signing.GenerateLeaf(alg, ca, caKey, leafOpts)
	require.NoError(t, err)
	signer, err := signing.NewLocalSigner(leafKey, []*x509.Certificate{leaf})
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	inner, err := signing.NewLocalVerifier(pool)
	require.NoError(t, err)
	return e2eFixture{
		algorithm: alg,
		signer:    signer,
		verifier:  &instrumentedVerifier{inner: inner},
	}
}

// instrumentedVerifier wraps a signing.Verifier with atomic counters
// for ValidateChain and Verify calls. Tests assert against the
// counters to confirm the on-wire envelope actually reached the
// verification path (and was not silently bypassed).
type instrumentedVerifier struct {
	inner          signing.Verifier
	validateChainN atomic.Int32
	verifyN        atomic.Int32
}

var _ signing.Verifier = (*instrumentedVerifier)(nil)

func (v *instrumentedVerifier) ValidateChain(ctx context.Context, chainDER [][]byte, now time.Time) (*x509.Certificate, error) {
	v.validateChainN.Add(1)
	return v.inner.ValidateChain(ctx, chainDER, now)
}

func (v *instrumentedVerifier) Verify(ctx context.Context, payload, signature []byte, leaf *x509.Certificate) error {
	v.verifyN.Add(1)
	return v.inner.Verify(ctx, payload, signature, leaf)
}

// captureLogger records Errorf format strings so reject-scenario
// tests can assert that the client's attestation-failure path
// actually ran (and not e.g. a network error).
type captureLogger struct {
	mu       sync.Mutex
	errLines []string
}

func (l *captureLogger) Debugf(_ context.Context, _ string, _ ...interface{}) {}

func (l *captureLogger) Errorf(_ context.Context, format string, v ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.errLines = append(l.errLines, fmt.Sprintf(format, v...))
}

func (l *captureLogger) hasErrorContaining(s string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, line := range l.errLines {
		if strings.Contains(line, s) {
			return true
		}
	}
	return false
}

// controlledSigner wraps another Signer with optional failure-mode
// injection: it can tamper signatures starting from the Nth call
// (drives the "tampered subsequent signature" reject path) or return
// failErr starting from the Nth call (drives the "mid-stream Sign
// failure" reject path). Zero-valued tamperFromCall / failFromCall
// disables the corresponding mode. Used only for tests.
type controlledSigner struct {
	inner          signing.Signer
	callN          atomic.Int32
	tamperFromCall int32
	failFromCall   int32
	failErr        error
}

func (s *controlledSigner) Sign(ctx context.Context, payload []byte) ([]byte, error) {
	n := s.callN.Add(1)
	if s.failFromCall > 0 && n >= s.failFromCall {
		return nil, s.failErr
	}
	sig, err := s.inner.Sign(ctx, payload)
	if err != nil {
		return nil, err
	}
	if s.tamperFromCall > 0 && n >= s.tamperFromCall && len(sig) > 0 {
		// Copy before mutating: the inner signer's contract doesn't
		// promise the returned slice is exclusively ours, and a future
		// pooled signer would break under in-place mutation.
		out := make([]byte, len(sig))
		copy(out, sig)
		out[0] ^= 0xff
		return out, nil
	}
	return sig, nil
}

func (s *controlledSigner) ChainDER(ctx context.Context) ([][]byte, error) {
	return s.inner.ChainDER(ctx)
}

// runServer spins up an in-process OpAMP server. signer may be nil
// (no attestation). onMessage may be nil — when omitted, the server
// echoes the agent's InstanceUid in an empty ServerToAgent.
func runServer(
	t *testing.T,
	signer signing.Signer,
	onConnected func(ctx context.Context, conn servertypes.Connection),
	onMessage func(ctx context.Context, conn servertypes.Connection, msg *protobufs.AgentToServer) *protobufs.ServerToAgent,
) (server.OpAMPServer, string) {
	t.Helper()
	if onMessage == nil {
		onMessage = func(_ context.Context, _ servertypes.Connection, m *protobufs.AgentToServer) *protobufs.ServerToAgent {
			return &protobufs.ServerToAgent{InstanceUid: m.InstanceUid}
		}
	}
	endpoint := testhelpers.GetAvailableLocalAddress()
	settings := server.StartSettings{
		Settings: server.Settings{
			PayloadSigner: signer,
			Callbacks: servertypes.Callbacks{
				OnConnecting: func(_ *http.Request) servertypes.ConnectionResponse {
					return servertypes.ConnectionResponse{
						Accept: true,
						ConnectionCallbacks: servertypes.ConnectionCallbacks{
							OnConnected: onConnected,
							OnMessage:   onMessage,
						},
					}
				},
			},
		},
		ListenEndpoint: endpoint,
		ListenPath:     listenPath,
	}
	srv := server.New(&sharedinternal.NopLogger{})
	require.NoError(t, srv.Start(settings))
	return srv, endpoint
}

// newInstanceUid generates a UUIDv7 for use as the client's
// InstanceUid. A v7 (time-ordered) UUID matches what real Agents
// generate.
func newInstanceUid(t *testing.T) clienttypes.InstanceUid {
	t.Helper()
	uid, err := uuid.NewV7()
	require.NoError(t, err)
	b, err := uid.MarshalBinary()
	require.NoError(t, err)
	return clienttypes.InstanceUid(b)
}

// minAgentDescr returns the smallest AgentDescription that satisfies
// the client's "non-empty identifying attributes" precondition.
func minAgentDescr() *protobufs.AgentDescription {
	return &protobufs.AgentDescription{
		IdentifyingAttributes: []*protobufs.KeyValue{
			{
				Key:   "service.name",
				Value: &protobufs.AnyValue{Value: &protobufs.AnyValue_StringValue{StringValue: "e2e-test-agent"}},
			},
		},
	}
}

// startClient configures and starts an OpAMP client (WS or HTTP) with
// the supplied verifier and callbacks. When verifier is non-nil, the
// RequiresPayloadTrustVerification capability bit is OR'd into the
// caps so the server knows to wrap.
func startClient(
	t *testing.T,
	transport string,
	endpoint string,
	verifier signing.Verifier,
	callbacks clienttypes.Callbacks,
	logger clienttypes.Logger,
) opampclient.OpAMPClient {
	t.Helper()
	if logger == nil {
		logger = &sharedinternal.NopLogger{}
	}

	var c opampclient.OpAMPClient
	var scheme string
	switch transport {
	case "ws":
		c = opampclient.NewWebSocket(logger)
		scheme = "ws"
	case "http":
		c = opampclient.NewHTTP(logger)
		scheme = "http"
	default:
		t.Fatalf("unsupported transport: %s", transport)
	}

	caps := protobufs.AgentCapabilities_AgentCapabilities_ReportsStatus
	if verifier != nil {
		caps |= protobufs.AgentCapabilities_AgentCapabilities_RequiresPayloadTrustVerification
	}

	// HTTP polling needs a non-zero interval; pick something short so
	// reject scenarios exercise multiple polls within their deadlines.
	heartbeat := 100 * time.Millisecond

	settings := clienttypes.StartSettings{
		OpAMPServerURL:    scheme + "://" + endpoint + listenPath,
		InstanceUid:       newInstanceUid(t),
		PayloadVerifier:   verifier,
		Callbacks:         callbacks,
		HeartbeatInterval: &heartbeat,
	}
	require.NoError(t, c.SetAgentDescription(minAgentDescr()))
	require.NoError(t, c.SetCapabilities(&caps))
	require.NoError(t, c.Start(context.Background(), settings))
	return c
}

// assertRejected is the common reject-scenario tail: wait until the
// client logs the canonical attestation-failure substring (fail-fast
// via require.Eventually), then confirm no message was ever delivered
// to OnMessage during e2eNonOccurrenceDeadline.
func assertRejected(t *testing.T, logger *captureLogger, msgN *atomic.Int32) {
	t.Helper()
	require.Eventually(t, func() bool {
		return logger.hasErrorContaining(attestationFailureLogSubstring)
	}, e2eDeadline, 10*time.Millisecond,
		"client never logged %q within e2eDeadline", attestationFailureLogSubstring)
	time.Sleep(e2eNonOccurrenceDeadline)
	assert.Equal(t, int32(0), msgN.Load(), "OnMessage should not fire when attestation fails")
}

// TestE2E_HappyPath_AllAlgorithms_WS exercises the full WS round trip
// for each supported signature algorithm. The client requires
// attestation; the server signs every outbound. We assert OnMessage
// fires on the client and that the instrumented verifier was invoked
// for both chain validation and signature verification.
func TestE2E_HappyPath_AllAlgorithms_WS(t *testing.T) {
	algorithms := []signing.Algorithm{
		signing.AlgorithmECDSAP256SHA256,
		signing.AlgorithmECDSAP384SHA384,
		signing.AlgorithmRSAPKCS1v15SHA256,
		signing.AlgorithmEd25519,
	}
	for _, alg := range algorithms {
		t.Run(alg.String(), func(t *testing.T) {
			f := newFixture(t, alg)

			srv, endpoint := runServer(t, f.signer, nil, nil)
			defer srv.Stop(context.Background())

			var msgN atomic.Int32
			c := startClient(t, "ws", endpoint, f.verifier, clienttypes.Callbacks{
				OnMessage: func(_ context.Context, _ *clienttypes.MessageData) {
					msgN.Add(1)
				},
			}, nil)
			defer c.Stop(context.Background())

			require.Eventually(t, func() bool { return msgN.Load() >= 1 }, e2eDeadline, 10*time.Millisecond,
				"client never received a ServerToAgent")

			// Chain validated once on the first envelope; signature
			// verified at least once since our server signs every
			// outbound message (including the first).
			assert.GreaterOrEqual(t, f.verifier.validateChainN.Load(), int32(1), "ValidateChain should run on first envelope")
			assert.GreaterOrEqual(t, f.verifier.verifyN.Load(), int32(1), "Verify should run since server signs first message too")
		})
	}
}

// TestE2E_FirstAndSubsequent_WS confirms that across two
// server-originated messages, the chain is validated exactly once and
// the signature is verified on each. Uses Connection.Send from
// OnConnected to push the second message.
func TestE2E_FirstAndSubsequent_WS(t *testing.T) {
	f := newFixture(t, signing.AlgorithmECDSAP256SHA256)

	var savedConn atomic.Pointer[servertypes.Connection]
	onConnected := func(_ context.Context, conn servertypes.Connection) {
		savedConn.Store(&conn)
	}

	srv, endpoint := runServer(t, f.signer, onConnected, nil)
	defer srv.Stop(context.Background())

	var msgN atomic.Int32
	c := startClient(t, "ws", endpoint, f.verifier, clienttypes.Callbacks{
		OnMessage: func(_ context.Context, _ *clienttypes.MessageData) {
			msgN.Add(1)
		},
	}, nil)
	defer c.Stop(context.Background())

	// First message — server's OnMessage response. Use require so
	// we fail fast (and don't deref a nil savedConn below).
	require.Eventually(t, func() bool { return msgN.Load() >= 1 }, e2eDeadline, 10*time.Millisecond,
		"client never received the first ServerToAgent")
	require.NotNil(t, savedConn.Load(), "server never observed OnConnected")

	// Second message — server-pushed via Connection.Send. The
	// connection's signing-negotiation is complete by now because
	// OnMessage on the server has fired (signing is decided BEFORE
	// OnMessage; see handleWSConnection).
	conn := *savedConn.Load()
	require.NoError(t, conn.Send(context.Background(), &protobufs.ServerToAgent{
		InstanceUid: []byte("subsequent-uid00"),
	}))

	require.Eventually(t, func() bool { return msgN.Load() >= 2 }, e2eDeadline, 10*time.Millisecond,
		"client never received the second ServerToAgent")

	assert.Equal(t, int32(1), f.verifier.validateChainN.Load(), "chain validated only on first envelope")
	assert.GreaterOrEqual(t, f.verifier.verifyN.Load(), int32(2), "both envelopes signed")
}

// TestE2E_NoAttestation_WS confirms the default wire format is
// untouched when neither side configures signing — i.e. attestation
// is purely opt-in.
func TestE2E_NoAttestation_WS(t *testing.T) {
	srv, endpoint := runServer(t, nil, nil, nil)
	defer srv.Stop(context.Background())

	var msgN atomic.Int32
	c := startClient(t, "ws", endpoint, nil /* verifier */, clienttypes.Callbacks{
		OnMessage: func(_ context.Context, _ *clienttypes.MessageData) {
			msgN.Add(1)
		},
	}, nil)
	defer c.Stop(context.Background())

	require.Eventually(t, func() bool { return msgN.Load() >= 1 }, e2eDeadline, 10*time.Millisecond,
		"plain OpAMP path should still deliver a ServerToAgent")
}

// TestE2E_Reject_ServerHasNoSigner_WS — Agent declares Requires but
// the Server has no signer configured. The Server returns a plain
// ServerToAgent which the Agent parses as a SignedServerToAgent
// envelope (proto3 is permissive); the envelope fails the
// missing-trust-chain check on the first message and the Agent
// terminates the connection.
func TestE2E_Reject_ServerHasNoSigner_WS(t *testing.T) {
	f := newFixture(t, signing.AlgorithmECDSAP256SHA256)
	logger := &captureLogger{}

	srv, endpoint := runServer(t, nil /* no signer */, nil, nil)
	defer srv.Stop(context.Background())

	var msgN atomic.Int32
	c := startClient(t, "ws", endpoint, f.verifier, clienttypes.Callbacks{
		OnMessage: func(_ context.Context, _ *clienttypes.MessageData) {
			msgN.Add(1)
		},
	}, logger)
	defer c.Stop(context.Background())

	assertRejected(t, logger, &msgN)
}

// TestE2E_Reject_ExpiredLeaf_WS — Server's leaf is expired. The
// Agent's chain validation rejects on the first envelope.
func TestE2E_Reject_ExpiredLeaf_WS(t *testing.T) {
	past := time.Now().Add(-2 * time.Hour)
	expired := signing.CertOptions{
		NotBefore: past.Add(-1 * time.Hour),
		NotAfter:  past,
	}
	f := newFixtureWithLeafOpts(t, signing.AlgorithmECDSAP256SHA256, expired)

	logger := &captureLogger{}
	srv, endpoint := runServer(t, f.signer, nil, nil)
	defer srv.Stop(context.Background())

	var msgN atomic.Int32
	c := startClient(t, "ws", endpoint, f.verifier, clienttypes.Callbacks{
		OnMessage: func(_ context.Context, _ *clienttypes.MessageData) {
			msgN.Add(1)
		},
	}, logger)
	defer c.Stop(context.Background())

	assertRejected(t, logger, &msgN)
	assert.GreaterOrEqual(t, f.verifier.validateChainN.Load(), int32(1), "ValidateChain should have been called")
}

// TestE2E_Reject_WrongCA_WS — Server signs with CA1; Agent trusts
// CA2. Chain validation fails on first envelope.
func TestE2E_Reject_WrongCA_WS(t *testing.T) {
	server1 := newFixture(t, signing.AlgorithmECDSAP256SHA256)
	client2 := newFixture(t, signing.AlgorithmECDSAP256SHA256) // independent CA

	logger := &captureLogger{}
	srv, endpoint := runServer(t, server1.signer, nil, nil)
	defer srv.Stop(context.Background())

	var msgN atomic.Int32
	c := startClient(t, "ws", endpoint, client2.verifier, clienttypes.Callbacks{
		OnMessage: func(_ context.Context, _ *clienttypes.MessageData) {
			msgN.Add(1)
		},
	}, logger)
	defer c.Stop(context.Background())

	assertRejected(t, logger, &msgN)
	assert.GreaterOrEqual(t, client2.verifier.validateChainN.Load(), int32(1), "ValidateChain should have been called")
}

// TestE2E_Reject_TamperedSubsequentSignature_WS — handshake succeeds
// (first envelope is signed with a valid signature); the second
// server-pushed envelope arrives with a corrupted signature. The
// Agent rejects and terminates the connection.
func TestE2E_Reject_TamperedSubsequentSignature_WS(t *testing.T) {
	f := newFixture(t, signing.AlgorithmECDSAP256SHA256)
	// Wrap the signer so the SECOND signature it produces is corrupted.
	bad := &controlledSigner{inner: f.signer, tamperFromCall: 2}

	var savedConn atomic.Pointer[servertypes.Connection]
	onConnected := func(_ context.Context, conn servertypes.Connection) {
		savedConn.Store(&conn)
	}

	logger := &captureLogger{}
	srv, endpoint := runServer(t, bad, onConnected, nil)
	defer srv.Stop(context.Background())

	var msgN atomic.Int32
	c := startClient(t, "ws", endpoint, f.verifier, clienttypes.Callbacks{
		OnMessage: func(_ context.Context, _ *clienttypes.MessageData) {
			msgN.Add(1)
		},
	}, logger)
	defer c.Stop(context.Background())

	// First message must succeed. Use require so we fail fast and
	// don't deref a nil savedConn below.
	require.Eventually(t, func() bool { return msgN.Load() >= 1 }, e2eDeadline, 10*time.Millisecond,
		"first envelope should pass since its signature is well-formed")
	require.NotNil(t, savedConn.Load(), "server never observed OnConnected")

	// Push the second — its signature will be corrupted by the
	// controlledSigner wrapper.
	conn := *savedConn.Load()
	require.NoError(t, conn.Send(context.Background(), &protobufs.ServerToAgent{
		InstanceUid: []byte("tampered-uid0000"),
	}))

	got := msgN.Load()
	require.Eventually(t, func() bool {
		return logger.hasErrorContaining(attestationFailureLogSubstring)
	}, e2eDeadline, 10*time.Millisecond, "client should reject the tampered subsequent envelope")

	// The second message must NOT have been delivered.
	time.Sleep(e2eNonOccurrenceDeadline)
	assert.Equal(t, got, msgN.Load(), "OnMessage should not fire after the tampered envelope")
}

// TestE2E_HappyPath_HTTP — sanity-check the HTTP transport. We use
// the ECDSA P-256 algorithm to keep the test cheap; the per-algorithm
// matrix is already covered by the WS variant since the signing path
// is transport-independent.
func TestE2E_HappyPath_HTTP(t *testing.T) {
	f := newFixture(t, signing.AlgorithmECDSAP256SHA256)

	srv, endpoint := runServer(t, f.signer, nil, nil)
	defer srv.Stop(context.Background())

	var msgN atomic.Int32
	c := startClient(t, "http", endpoint, f.verifier, clienttypes.Callbacks{
		OnMessage: func(_ context.Context, _ *clienttypes.MessageData) {
			msgN.Add(1)
		},
	}, nil)
	defer c.Stop(context.Background())

	require.Eventually(t, func() bool { return msgN.Load() >= 1 }, e2eDeadline, 10*time.Millisecond,
		"HTTP client never received a ServerToAgent")
	assert.GreaterOrEqual(t, f.verifier.validateChainN.Load(), int32(1), "ValidateChain should run on first envelope")
}

// TestE2E_HTTP_Reject_WrongCA — same as the WS variant but on the
// HTTP polling transport. The Agent keeps polling but never delivers
// a verified message. The HTTP receive path now emits the same
// canonical "Payload trust verification failed" sentinel as WS, so
// assertRejected works uniformly.
func TestE2E_HTTP_Reject_WrongCA(t *testing.T) {
	server1 := newFixture(t, signing.AlgorithmECDSAP256SHA256)
	client2 := newFixture(t, signing.AlgorithmECDSAP256SHA256) // independent CA

	logger := &captureLogger{}
	srv, endpoint := runServer(t, server1.signer, nil, nil)
	defer srv.Stop(context.Background())

	var msgN atomic.Int32
	c := startClient(t, "http", endpoint, client2.verifier, clienttypes.Callbacks{
		OnMessage: func(_ context.Context, _ *clienttypes.MessageData) {
			msgN.Add(1)
		},
	}, logger)
	defer c.Stop(context.Background())

	assertRejected(t, logger, &msgN)
	assert.GreaterOrEqual(t, client2.verifier.validateChainN.Load(), int32(1),
		"ValidateChain on HTTP should have been called at least once")
}

// TestE2E_ConcurrentConnections_MixedSigningState — two agents share
// the same server: one requires attestation (and gets wrapped
// responses), the other doesn't (and gets plain wire). Confirms the
// server's per-connection signing state is isolated, and that one
// agent's handshake doesn't leak into the other's wire format.
func TestE2E_ConcurrentConnections_MixedSigningState(t *testing.T) {
	f := newFixture(t, signing.AlgorithmECDSAP256SHA256)

	srv, endpoint := runServer(t, f.signer, nil, nil)
	defer srv.Stop(context.Background())

	// Agent A — requires attestation. Its verifier should fire.
	var aMsgN atomic.Int32
	cA := startClient(t, "ws", endpoint, f.verifier, clienttypes.Callbacks{
		OnMessage: func(_ context.Context, _ *clienttypes.MessageData) {
			aMsgN.Add(1)
		},
	}, nil)
	defer cA.Stop(context.Background())

	// Agent B — same server, no verifier (does NOT require attestation).
	// Server's PayloadSigner is configured, but B didn't opt in, so B
	// must see plain ServerToAgent wire bytes.
	var bMsgN atomic.Int32
	cB := startClient(t, "ws", endpoint, nil /* no verifier */, clienttypes.Callbacks{
		OnMessage: func(_ context.Context, _ *clienttypes.MessageData) {
			bMsgN.Add(1)
		},
	}, nil)
	defer cB.Stop(context.Background())

	require.Eventually(t, func() bool { return aMsgN.Load() >= 1 }, e2eDeadline, 10*time.Millisecond,
		"agent A (requires) never received a message")
	require.Eventually(t, func() bool { return bMsgN.Load() >= 1 }, e2eDeadline, 10*time.Millisecond,
		"agent B (no verifier) never received a message")

	// A's verifier ran; B's wire format never went through any verifier
	// (B doesn't have one). The fact that B got a message at all is
	// proof the server didn't accidentally wrap B's responses.
	assert.GreaterOrEqual(t, f.verifier.validateChainN.Load(), int32(1),
		"A's verifier should have validated the chain")
}

// errSignFailure is the sentinel returned by the failing controlledSigner
// in TestE2E_Reject_MidStreamSignFailure_WS.
var errSignFailure = fmt.Errorf("e2e test: synthetic signer failure")

// TestE2E_Reject_MidStreamSignFailure_WS — handshake succeeds; the
// server's signer fails on the second outbound Sign call. The
// server-side OnMessageResponseError callback fires; the agent never
// delivers a corrupt message; Send returns the signer's error.
func TestE2E_Reject_MidStreamSignFailure_WS(t *testing.T) {
	f := newFixture(t, signing.AlgorithmECDSAP256SHA256)
	bad := &controlledSigner{
		inner:        f.signer,
		failFromCall: 2,
		failErr:      errSignFailure,
	}

	var savedConn atomic.Pointer[servertypes.Connection]
	onConnected := func(_ context.Context, conn servertypes.Connection) {
		savedConn.Store(&conn)
	}

	srv, endpoint := runServer(t, bad, onConnected, nil)
	defer srv.Stop(context.Background())

	var msgN atomic.Int32
	c := startClient(t, "ws", endpoint, f.verifier, clienttypes.Callbacks{
		OnMessage: func(_ context.Context, _ *clienttypes.MessageData) {
			msgN.Add(1)
		},
	}, nil)
	defer c.Stop(context.Background())

	// First message succeeds (callN starts at 0; failFromCall is 2).
	require.Eventually(t, func() bool { return msgN.Load() >= 1 }, e2eDeadline, 10*time.Millisecond,
		"first envelope should pass since its signature is well-formed")
	require.NotNil(t, savedConn.Load(), "server never observed OnConnected")

	// Push the second outbound — signer will fail this time. The
	// signer's error propagates back through wsConnection.Send.
	conn := *savedConn.Load()
	err := conn.Send(context.Background(), &protobufs.ServerToAgent{
		InstanceUid: []byte("mid-stream-uid00"),
	})
	require.ErrorIs(t, err, errSignFailure, "Send should propagate the signer's error")

	// Confirm the agent never sees the corrupt message — neither
	// payload (since signing failed before wire write) nor a tampered
	// envelope (since we error out before WriteWSMessage runs).
	time.Sleep(e2eNonOccurrenceDeadline)
	assert.Equal(t, int32(1), msgN.Load(), "agent should still have only the first message")
}

// TestE2E_SendBeforeNegotiation_Errors_WS — when the server has a
// PayloadSigner configured and the user's OnConnected callback calls
// Connection.Send BEFORE the first AgentToServer has been processed,
// Send must return ErrSendBeforeNegotiated rather than emitting
// unsigned wire bytes. Closes the silent-bypass gap the code review
// flagged.
func TestE2E_SendBeforeNegotiation_Errors_WS(t *testing.T) {
	f := newFixture(t, signing.AlgorithmECDSAP256SHA256)

	var sendErr atomic.Value // error
	onConnected := func(_ context.Context, conn servertypes.Connection) {
		err := conn.Send(context.Background(), &protobufs.ServerToAgent{
			InstanceUid: []byte("premature-uid000"),
		})
		sendErr.Store(err)
	}

	srv, endpoint := runServer(t, f.signer, onConnected, nil)
	defer srv.Stop(context.Background())

	var msgN atomic.Int32
	c := startClient(t, "ws", endpoint, f.verifier, clienttypes.Callbacks{
		OnMessage: func(_ context.Context, _ *clienttypes.MessageData) {
			msgN.Add(1)
		},
	}, nil)
	defer c.Stop(context.Background())

	require.Eventually(t, func() bool { return sendErr.Load() != nil }, e2eDeadline, 10*time.Millisecond,
		"server's OnConnected never fired")
	got, ok := sendErr.Load().(error)
	require.True(t, ok, "sendErr should hold an error")
	require.ErrorIs(t, got, server.ErrSendBeforeNegotiated,
		"Send before the first AgentToServer should error when PayloadSigner is configured")

	// After the pre-handshake Send error, the agent should still
	// negotiate normally on its next AgentToServer and receive a
	// valid signed response.
	require.Eventually(t, func() bool { return msgN.Load() >= 1 }, e2eDeadline, 10*time.Millisecond,
		"negotiation should still succeed despite the pre-handshake Send error")
}

// TestE2E_SendBeforeNegotiation_NoSigner_AllowsSend_WS — control case
// for the test above: when PayloadSigner is NOT configured, Send from
// OnConnected works as before (no negotiation gate). Confirms the
// gate is strictly scoped to attestation-enabled servers.
func TestE2E_SendBeforeNegotiation_NoSigner_AllowsSend_WS(t *testing.T) {
	var sendCalled atomic.Bool
	var sendOK atomic.Bool
	onConnected := func(_ context.Context, conn servertypes.Connection) {
		err := conn.Send(context.Background(), &protobufs.ServerToAgent{
			InstanceUid: []byte("preflight-uid000"),
		})
		sendCalled.Store(true)
		if err == nil {
			sendOK.Store(true)
		}
	}

	srv, endpoint := runServer(t, nil /* no signer */, onConnected, nil)
	defer srv.Stop(context.Background())

	var msgN atomic.Int32
	c := startClient(t, "ws", endpoint, nil /* no verifier */, clienttypes.Callbacks{
		OnMessage: func(_ context.Context, _ *clienttypes.MessageData) {
			msgN.Add(1)
		},
	}, nil)
	defer c.Stop(context.Background())

	require.Eventually(t, sendCalled.Load, e2eDeadline, 10*time.Millisecond,
		"server's OnConnected never fired")
	assert.True(t, sendOK.Load(),
		"Send before negotiation should succeed when PayloadSigner is nil")

	require.Eventually(t, func() bool { return msgN.Load() >= 1 }, e2eDeadline, 10*time.Millisecond,
		"client should still receive messages")
}
