package internal

import (
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/open-telemetry/opamp-go/protobufs"
	"github.com/open-telemetry/opamp-go/signing"
)

// TestValidateCapabilities_AttestationCapabilityRequiresVerifier
// covers the new consistency check between the
// AgentCapabilities_RequiresPayloadTrustVerification bit and
// ClientCommon.PayloadVerifier.
func TestValidateCapabilities_AttestationCapabilityRequiresVerifier(t *testing.T) {
	requiresBit := protobufs.AgentCapabilities_AgentCapabilities_RequiresPayloadTrustVerification

	t.Run("capability set + verifier nil → ErrPayloadVerifierMissing", func(t *testing.T) {
		var c ClientCommon
		err := c.validateCapabilities(requiresBit)
		require.ErrorIs(t, err, ErrPayloadVerifierMissing)
	})

	t.Run("capability not set + verifier non-nil → ErrPayloadVerifierWithoutCapability", func(t *testing.T) {
		verifier, err := signing.NewLocalVerifier(x509.NewCertPool())
		require.NoError(t, err)
		c := ClientCommon{PayloadVerifier: verifier}

		err = c.validateCapabilities(0)
		require.ErrorIs(t, err, ErrPayloadVerifierWithoutCapability)
	})

	t.Run("capability set + verifier non-nil → ok", func(t *testing.T) {
		verifier, err := signing.NewLocalVerifier(x509.NewCertPool())
		require.NoError(t, err)
		c := ClientCommon{PayloadVerifier: verifier}

		require.NoError(t, c.validateCapabilities(requiresBit))
	})

	t.Run("neither set → ok (default opt-out)", func(t *testing.T) {
		var c ClientCommon
		require.NoError(t, c.validateCapabilities(0))
	})
}
