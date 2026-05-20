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
	// Generous so RSA key generation on slow CI doesn't flake.
	e2eDeadline = 5 * time.Second
	// e2eNonOccurrenceDeadline bounds the wait for a "this should NOT
	// happen" assertion (reject scenarios assert OnMessage never
	// fires). Tradeoff: too short hides slow paths; too long slows the
	// suite. 750ms catches anything that would have happened on a
	// healthy local box.
	e2eNonOccurrenceDeadline = 750 * time.Millisecond
	// listenPath is shared by all e2e tests; ws/http URL building
	// concatenates it to the dialed endpoint.
	listenPath = "/v1/opamp"
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

// tamperingSigner wraps another Signer and corrupts the signature
// bytes starting from the Nth call (1-indexed). Used to exercise the
// "subsequent-message tampered signature" reject path while still
// letting the first envelope's handshake succeed.
type tamperingSigner struct {
	inner          signing.Signer
	callN          atomic.Int32
	tamperFromCall int32
}

func (t *tamperingSigner) Sign(ctx context.Context, payload []byte) ([]byte, error) {
	n := t.callN.Add(1)
	sig, err := t.inner.Sign(ctx, payload)
	if err != nil {
		return nil, err
	}
	if n >= t.tamperFromCall && len(sig) > 0 {
		sig[0] ^= 0xff
	}
	return sig, nil
}

func (t *tamperingSigner) ChainDER(ctx context.Context) ([][]byte, error) {
	return t.inner.ChainDER(ctx)
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

			assert.Eventually(t, func() bool { return msgN.Load() >= 1 }, e2eDeadline, 10*time.Millisecond,
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

	// First message — server's OnMessage response.
	assert.Eventually(t, func() bool { return msgN.Load() >= 1 }, e2eDeadline, 10*time.Millisecond,
		"client never received the first ServerToAgent")
	require.NotNil(t, savedConn.Load(), "server never observed OnConnected")

	// Second message — server-pushed via Connection.Send.
	conn := *savedConn.Load()
	require.NoError(t, conn.Send(context.Background(), &protobufs.ServerToAgent{
		InstanceUid: []byte("subsequent-uid00"),
	}))

	assert.Eventually(t, func() bool { return msgN.Load() >= 2 }, e2eDeadline, 10*time.Millisecond,
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

	assert.Eventually(t, func() bool { return msgN.Load() >= 1 }, e2eDeadline, 10*time.Millisecond,
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

	// Wait long enough for the Agent to receive at least one bad
	// envelope and tear the connection down.
	assert.Eventually(t, func() bool {
		return logger.hasErrorContaining("Payload trust verification failed")
	}, e2eDeadline, 10*time.Millisecond, "client never logged an attestation failure")

	// The Agent must NOT deliver any message that failed verification.
	time.Sleep(e2eNonOccurrenceDeadline)
	assert.Equal(t, int32(0), msgN.Load(), "OnMessage should not fire when attestation fails")
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

	assert.Eventually(t, func() bool {
		return logger.hasErrorContaining("Payload trust verification failed")
	}, e2eDeadline, 10*time.Millisecond, "client should reject expired leaf")
	time.Sleep(e2eNonOccurrenceDeadline)
	assert.Equal(t, int32(0), msgN.Load(), "OnMessage should not fire for expired leaf")
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

	assert.Eventually(t, func() bool {
		return logger.hasErrorContaining("Payload trust verification failed")
	}, e2eDeadline, 10*time.Millisecond, "client should reject chain from an unknown CA")
	time.Sleep(e2eNonOccurrenceDeadline)
	assert.Equal(t, int32(0), msgN.Load(), "OnMessage should not fire for unknown CA")
	assert.GreaterOrEqual(t, client2.verifier.validateChainN.Load(), int32(1), "ValidateChain should have been called")
}

// TestE2E_Reject_TamperedSubsequentSignature_WS — handshake succeeds
// (first envelope is signed with a valid signature); the second
// server-pushed envelope arrives with a corrupted signature. The
// Agent rejects and terminates the connection.
func TestE2E_Reject_TamperedSubsequentSignature_WS(t *testing.T) {
	f := newFixture(t, signing.AlgorithmECDSAP256SHA256)
	// Wrap the signer so the SECOND signature it produces is corrupted.
	bad := &tamperingSigner{inner: f.signer, tamperFromCall: 2}

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

	// First message must succeed.
	assert.Eventually(t, func() bool { return msgN.Load() >= 1 }, e2eDeadline, 10*time.Millisecond,
		"first envelope should pass since its signature is well-formed")

	// Push the second — its signature will be corrupted by the
	// tamperingSigner wrapper.
	conn := *savedConn.Load()
	require.NoError(t, conn.Send(context.Background(), &protobufs.ServerToAgent{
		InstanceUid: []byte("tampered-uid0000"),
	}))

	assert.Eventually(t, func() bool {
		return logger.hasErrorContaining("Payload trust verification failed")
	}, e2eDeadline, 10*time.Millisecond, "client should reject the tampered subsequent envelope")

	// The second message must NOT have been delivered.
	got := msgN.Load()
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

	assert.Eventually(t, func() bool { return msgN.Load() >= 1 }, e2eDeadline, 10*time.Millisecond,
		"HTTP client never received a ServerToAgent")
	assert.GreaterOrEqual(t, f.verifier.validateChainN.Load(), int32(1), "ValidateChain should run on first envelope")
}

// TestE2E_HTTP_Reject_WrongCA — same as the WS variant but on the
// HTTP polling transport. The Agent keeps polling but never delivers
// a verified message.
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

	assert.Eventually(t, func() bool {
		return logger.hasErrorContaining("cannot unmarshal response")
	}, e2eDeadline, 10*time.Millisecond, "HTTP client should reject chain from an unknown CA")
	time.Sleep(e2eNonOccurrenceDeadline)
	assert.Equal(t, int32(0), msgN.Load(), "OnMessage should not fire when HTTP attestation fails")
	assert.GreaterOrEqual(t, client2.verifier.validateChainN.Load(), int32(1), "ValidateChain should have been called")
}
