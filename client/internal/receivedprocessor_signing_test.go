package internal

import (
	"context"
	"crypto/x509"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sharedinternal "github.com/open-telemetry/opamp-go/internal"
	"github.com/open-telemetry/opamp-go/client/types"
	"github.com/open-telemetry/opamp-go/protobufs"
	"github.com/open-telemetry/opamp-go/signing"
)

// makeRemoteConfigSigningSetup generates a CA, leaf cert, ConfigSigner, and verifier.
func makeRemoteConfigSigningSetup(t *testing.T) (*signing.ConfigSigner, *signing.X509SignatureVerifier) {
	t.Helper()
	caKey, caCert, caCertPEM, err := signing.GenerateECDSACA()
	require.NoError(t, err)

	leafTLS, leafChainPEM, err := signing.GenerateECDSALeafCert(caCert, caKey)
	require.NoError(t, err)

	cs, err := signing.NewConfigSigner(leafTLS, leafChainPEM)
	require.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caCertPEM)
	return cs, signing.NewX509SignatureVerifier(pool)
}

// runProcessorWithRemoteConfig creates a receivedProcessor with the given verifier and
// capabilities, delivers a ServerToAgent containing remoteConfig, and returns whether
// OnMessage was called with a non-nil RemoteConfig and the RemoteConfigStatus queued
// on the sender (nil if no status update was scheduled).
func runProcessorWithRemoteConfig(
	t *testing.T,
	remoteConfig *protobufs.AgentRemoteConfig,
	verifier signing.SignatureVerifier,
	capabilities protobufs.AgentCapabilities,
) (deliveredToOnMessage bool, sentStatus *protobufs.RemoteConfigStatus) {
	t.Helper()

	callbacks := types.Callbacks{
		OnMessage: func(_ context.Context, msg *types.MessageData) {
			if msg.RemoteConfig != nil {
				deliveredToOnMessage = true
			}
		},
	}
	callbacks.SetDefaults()

	clientSyncedState := ClientSyncedState{
		remoteConfigStatus: &protobufs.RemoteConfigStatus{
			LastRemoteConfigHash: []byte("previous-hash"),
		},
	}
	clientSyncedState.SetCapabilities(&capabilities)

	sender := NewMockSender()

	proc := newReceivedProcessor(
		&sharedinternal.NopLogger{},
		callbacks,
		sender,
		&clientSyncedState,
		nil,
		new(sync.Mutex),
		time.Second,
		verifier,
	)

	proc.ProcessReceivedMessage(context.Background(), &protobufs.ServerToAgent{
		RemoteConfig: remoteConfig,
	})

	// Retrieve whatever RemoteConfigStatus was queued on the sender, if any.
	if msg := sender.NextMessage().PopPending(); msg != nil {
		sentStatus = msg.RemoteConfigStatus
	}
	return deliveredToOnMessage, sentStatus
}

func TestReceivedProcessor_ValidSignatureDelivered(t *testing.T) {
	configSigner, verifier := makeRemoteConfigSigningSetup(t)

	config := &protobufs.AgentRemoteConfig{
		Config: &protobufs.AgentConfigMap{
			ConfigMap: map[string]*protobufs.AgentConfigFile{
				"app.yaml": {Body: []byte("key: value")},
			},
		},
		ConfigHash: []byte("hash-v1"),
	}
	require.NoError(t, configSigner.SignConfig(config))

	caps := protobufs.AgentCapabilities_AgentCapabilities_AcceptsRemoteConfig |
		protobufs.AgentCapabilities_AgentCapabilities_VerifiesRemoteConfigSignature |
		protobufs.AgentCapabilities_AgentCapabilities_ReportsStatus

	delivered, status := runProcessorWithRemoteConfig(t, config, verifier, caps)
	assert.True(t, delivered, "valid config must be delivered to OnMessage")
	assert.Nil(t, status, "no status update should be sent for a valid config")
}

func TestReceivedProcessor_InvalidSignatureRejected(t *testing.T) {
	configSigner, _ := makeRemoteConfigSigningSetup(t)

	config := &protobufs.AgentRemoteConfig{
		Config: &protobufs.AgentConfigMap{
			ConfigMap: map[string]*protobufs.AgentConfigFile{
				"app.yaml": {Body: []byte("key: value")},
			},
		},
		ConfigHash: []byte("hash-v1"),
	}
	require.NoError(t, configSigner.SignConfig(config))

	// Verifier trusts a different CA so the signature fails.
	_, _, otherCAPEM, err := signing.GenerateECDSACA()
	require.NoError(t, err)
	otherPool := x509.NewCertPool()
	otherPool.AppendCertsFromPEM(otherCAPEM)
	wrongVerifier := signing.NewX509SignatureVerifier(otherPool)

	caps := protobufs.AgentCapabilities_AgentCapabilities_AcceptsRemoteConfig |
		protobufs.AgentCapabilities_AgentCapabilities_VerifiesRemoteConfigSignature |
		protobufs.AgentCapabilities_AgentCapabilities_ReportsStatus

	delivered, status := runProcessorWithRemoteConfig(t, config, wrongVerifier, caps)
	assert.False(t, delivered, "config with invalid signature must not reach OnMessage")
	require.NotNil(t, status, "RemoteConfigStatus FAILED must be sent on signature failure")
	assert.Equal(t, protobufs.RemoteConfigStatuses_RemoteConfigStatuses_FAILED, status.Status)
	// Hash must be the rejected config's hash, not the previously applied hash.
	assert.Equal(t, []byte("hash-v1"), status.LastRemoteConfigHash,
		"LastRemoteConfigHash must be the rejected config's hash to avoid server resend loop")
	assert.Contains(t, status.ErrorMessage, "signature verification failed")
}

func TestReceivedProcessor_MissingSignatureRejected(t *testing.T) {
	_, verifier := makeRemoteConfigSigningSetup(t)

	// Config is not signed at all.
	config := &protobufs.AgentRemoteConfig{
		Config: &protobufs.AgentConfigMap{
			ConfigMap: map[string]*protobufs.AgentConfigFile{
				"app.yaml": {Body: []byte("key: value")},
			},
		},
		ConfigHash: []byte("hash-v2"),
	}

	caps := protobufs.AgentCapabilities_AgentCapabilities_AcceptsRemoteConfig |
		protobufs.AgentCapabilities_AgentCapabilities_VerifiesRemoteConfigSignature |
		protobufs.AgentCapabilities_AgentCapabilities_ReportsStatus

	delivered, status := runProcessorWithRemoteConfig(t, config, verifier, caps)
	assert.False(t, delivered, "unsigned config must not reach OnMessage")
	require.NotNil(t, status)
	assert.Equal(t, protobufs.RemoteConfigStatuses_RemoteConfigStatuses_FAILED, status.Status)
	assert.Equal(t, []byte("hash-v2"), status.LastRemoteConfigHash)
	assert.Contains(t, status.ErrorMessage, "signature verification failed")
}

func TestReceivedProcessor_SignatureIgnoredWithoutCapability(t *testing.T) {
	// VerifiesRemoteConfigSignature not declared — config must be delivered regardless
	// of signature validity.
	configSigner, _ := makeRemoteConfigSigningSetup(t)

	// Use a wrong-CA verifier to confirm verification is actually skipped, not just passing.
	_, _, otherCAPEM, err := signing.GenerateECDSACA()
	require.NoError(t, err)
	otherPool := x509.NewCertPool()
	otherPool.AppendCertsFromPEM(otherCAPEM)
	wrongVerifier := signing.NewX509SignatureVerifier(otherPool)

	config := &protobufs.AgentRemoteConfig{
		Config: &protobufs.AgentConfigMap{
			ConfigMap: map[string]*protobufs.AgentConfigFile{
				"app.yaml": {Body: []byte("key: value")},
			},
		},
		ConfigHash: []byte("hash-v3"),
	}
	require.NoError(t, configSigner.SignConfig(config))

	// AcceptsRemoteConfig but NOT VerifiesRemoteConfigSignature.
	caps := protobufs.AgentCapabilities_AgentCapabilities_AcceptsRemoteConfig |
		protobufs.AgentCapabilities_AgentCapabilities_ReportsStatus

	delivered, status := runProcessorWithRemoteConfig(t, config, wrongVerifier, caps)
	assert.True(t, delivered, "config must be delivered when verification capability is not set")
	assert.Nil(t, status)
}

func TestReceivedProcessor_NilVerifierWithCapabilityFails(t *testing.T) {
	// When VerifiesRemoteConfigSignature is set but signatureVerifier is nil,
	// the processor must hard-reject the config and report FAILED — not silently
	// deliver it. validateCapabilities prevents this at Start() time; this test
	// confirms the processor's own guard also produces the correct outcome.
	config := &protobufs.AgentRemoteConfig{
		Config: &protobufs.AgentConfigMap{
			ConfigMap: map[string]*protobufs.AgentConfigFile{
				"app.yaml": {Body: []byte("key: value")},
			},
		},
		ConfigHash: []byte("hash-v1"),
	}

	caps := protobufs.AgentCapabilities_AgentCapabilities_AcceptsRemoteConfig |
		protobufs.AgentCapabilities_AgentCapabilities_VerifiesRemoteConfigSignature |
		protobufs.AgentCapabilities_AgentCapabilities_ReportsStatus

	// nil verifier with the capability set
	delivered, status := runProcessorWithRemoteConfig(t, config, nil, caps)
	assert.False(t, delivered, "config must not reach OnMessage when verifier is nil")
	require.NotNil(t, status, "FAILED status must be sent")
	assert.Equal(t, protobufs.RemoteConfigStatuses_RemoteConfigStatuses_FAILED, status.Status)
	assert.Contains(t, status.ErrorMessage, "SignatureVerifier is not configured")
}

func TestClientCommon_ErrSignatureVerifierRequired(t *testing.T) {
	// PrepareStart (via validateCapabilities) must reject a signing capability
	// when no SignatureVerifier is provided — covers both signing capability bits.
	common := NewClientCommon(&sharedinternal.NopLogger{}, NewMockSender())

	t.Run("VerifiesRemoteConfigSignature", func(t *testing.T) {
		caps := protobufs.AgentCapabilities_AgentCapabilities_ReportsStatus |
			protobufs.AgentCapabilities_AgentCapabilities_VerifiesRemoteConfigSignature
		require.NoError(t, common.ClientSyncedState.SetCapabilities(&caps))
		err := common.validateCapabilities(caps)
		assert.ErrorIs(t, err, ErrSignatureVerifierRequired)
	})

	t.Run("VerifiesPackageSignatures", func(t *testing.T) {
		caps := protobufs.AgentCapabilities_AgentCapabilities_ReportsStatus |
			protobufs.AgentCapabilities_AgentCapabilities_AcceptsPackages |
			protobufs.AgentCapabilities_AgentCapabilities_ReportsPackageStatuses |
			protobufs.AgentCapabilities_AgentCapabilities_VerifiesPackageSignatures
		require.NoError(t, common.ClientSyncedState.SetCapabilities(&caps))
		// PackagesStateProvider must be non-nil for AcceptsPackages capability.
		common.PackagesStateProvider = NewInMemPackagesStore()
		err := common.validateCapabilities(caps)
		assert.ErrorIs(t, err, ErrSignatureVerifierRequired)
	})
}
