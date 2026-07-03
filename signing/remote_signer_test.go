package signing_test

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/open-telemetry/opamp-go/signing"
)

func TestRemoteSigner_Sign_HappyPath(t *testing.T) {
	const wantSig = "fake-signature-bytes"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/v1/sign", r.URL.Path)
		_, _ = w.Write([]byte(wantSig))
	}))
	defer srv.Close()

	s := signing.NewRemoteSigner(srv.URL)
	sig, err := s.Sign(context.Background(), []byte("test-payload"))
	require.NoError(t, err)
	require.Equal(t, []byte(wantSig), sig)
}

func TestRemoteSigner_Sign_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "policy denied", http.StatusForbidden)
	}))
	defer srv.Close()

	s := signing.NewRemoteSigner(srv.URL)
	_, err := s.Sign(context.Background(), []byte("test-payload"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "403")
}

func TestRemoteSigner_ChainDER_HappyPath(t *testing.T) {
	ca, caKey, err := signing.GenerateCA(signing.AlgorithmECDSAP256SHA256, signing.CertOptions{})
	require.NoError(t, err)
	leaf, _, err := signing.GenerateLeaf(signing.AlgorithmECDSAP256SHA256, ca, caKey, signing.CertOptions{})
	require.NoError(t, err)

	// Server returns PEM chain (leaf only in this test).
	pemChain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, "/v1/chain", r.URL.Path)
		_, _ = w.Write(pemChain)
	}))
	defer srv.Close()

	s := signing.NewRemoteSigner(srv.URL)
	chain, err := s.ChainDER(context.Background())
	require.NoError(t, err)
	require.Len(t, chain, 1)
	require.Equal(t, leaf.Raw, chain[0])
}

func TestRemoteSigner_ChainDER_EmptyBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK) // 200 but no PEM blocks
	}))
	defer srv.Close()

	s := signing.NewRemoteSigner(srv.URL)
	_, err := s.ChainDER(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "no CERTIFICATE PEM blocks")
}

func TestRemoteSigner_ChainDER_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	s := signing.NewRemoteSigner(srv.URL)
	_, err := s.ChainDER(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "503")
}

func TestRemoteSigner_TrailingSlashStripped(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		require.Equal(t, "/v1/sign", r.URL.Path)
		_, _ = w.Write([]byte("sig"))
	}))
	defer srv.Close()

	// Pass URL with trailing slash — NewRemoteSigner must strip it.
	s := signing.NewRemoteSigner(srv.URL + "/")
	_, err := s.Sign(context.Background(), []byte("p"))
	require.NoError(t, err)
	require.True(t, called)
}
