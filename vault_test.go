package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	"github.com/tinfoilsh/encrypted-http-body-protocol/protocol"
)

// vaultProbe is a stand-in for the real vault enclave: it serves the EHBP key
// config and a /store endpoint behind the decrypting middleware, and records
// both the raw bytes the host would see and the decrypted request. Lets us
// exercise the write path without a live, attested enclave.
type vaultProbe struct {
	server  *httptest.Server
	id      *identity.Identity
	got     storeRequest
	rawBody []byte
}

func mockVault(t *testing.T) *vaultProbe {
	t.Helper()
	id, err := identity.NewIdentity()
	require.NoError(t, err)
	p := &vaultProbe{id: id}

	store := id.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := json.Unmarshal(body, &p.got); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))

	mux := http.NewServeMux()
	mux.HandleFunc(protocol.KeysPath, id.ConfigHandler)
	// Capture the wire bytes before the middleware decrypts, then replay them in.
	mux.Handle("/store", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		p.rawBody = raw
		r.Body = io.NopCloser(bytes.NewReader(raw))
		store.ServeHTTP(w, r)
	}))

	p.server = httptest.NewServer(mux)
	t.Cleanup(p.server.Close)
	return p
}

func TestVaultPutRoundTrip(t *testing.T) {
	p := mockVault(t)

	hc, err := ehbpClientPinned(p.server.URL, p.id.MarshalPublicKeyHex())
	require.NoError(t, err)

	require.NoError(t, vaultPut(hc, p.server.URL, "me/my-workload", "DB_PASSWORD", "s3cret"))

	require.Equal(t, storeRequest{Repo: "me/my-workload", Name: "DB_PASSWORD", Value: "s3cret"}, p.got)
	require.NotEmpty(t, p.rawBody)
	require.NotContains(t, string(p.rawBody), "s3cret", "plaintext value must not appear on the wire")
}

func TestEHBPClientPinnedRejectsKeyMismatch(t *testing.T) {
	p := mockVault(t)

	_, err := ehbpClientPinned(p.server.URL, strings.Repeat("00", 32))
	require.Error(t, err)
	require.Contains(t, err.Error(), "mismatch")
}

func TestVaultList(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/secrets", func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, "me/my-workload", r.URL.Query().Get("repo"))
		_ = json.NewEncoder(w).Encode(map[string][]string{"secrets": {"A", "B"}})
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	names, err := vaultList(ts.URL, "me/my-workload")
	require.NoError(t, err)
	require.Equal(t, []string{"A", "B"}, names)
}

func TestVaultRemove(t *testing.T) {
	var method, repo, name string
	mux := http.NewServeMux()
	mux.HandleFunc("/secrets", func(w http.ResponseWriter, r *http.Request) {
		method, repo, name = r.Method, r.URL.Query().Get("repo"), r.URL.Query().Get("name")
		w.WriteHeader(http.StatusNoContent)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	require.NoError(t, vaultRemove(ts.URL, "me/my-workload", "DB_PASSWORD"))
	require.Equal(t, http.MethodDelete, method)
	require.Equal(t, "me/my-workload", repo)
	require.Equal(t, "DB_PASSWORD", name)
}
