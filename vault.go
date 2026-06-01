package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	ehbp "github.com/tinfoilsh/encrypted-http-body-protocol/client"
	"github.com/tinfoilsh/tinfoil-go/verifier/client"
)

const (
	defaultVaultRepo = "tinfoilsh/confidential-secrets-vault"
	envVaultURL      = "TINFOIL_VAULT_URL"
)

var (
	vaultHost      string
	vaultRepo      string
	vaultOwnerRepo string
	vaultHPKEKey   string

	errNoVaultHost = fmt.Errorf("no vault host: pass --vault or set $%s", envVaultURL)
	errNoOwnerRepo = fmt.Errorf("--repo is required: the repo whose attested workloads may fetch the secret")
)

func init() {
	rootCmd.AddCommand(vaultCmd)
	vaultCmd.PersistentFlags().StringVar(&vaultHost, "vault", "", "Vault host, e.g. secrets.tinfoil.sh (overrides $"+envVaultURL+")")
	vaultCmd.PersistentFlags().StringVar(&vaultRepo, "vault-repo", defaultVaultRepo, "Source repo of the vault enclave, used to attest it")
	vaultCmd.PersistentFlags().StringVar(&vaultOwnerRepo, "repo", "", "Repo whose attested workloads may fetch the secret (the tenant key)")
	vaultCmd.PersistentFlags().StringVar(&vaultHPKEKey, "vault-hpke-key", "", "Pin this HPKE key (hex) instead of attesting the vault — testing only, bypasses verification")

	vaultPutCmd.Flags().StringVar(&secretValue, "value", "", "Secret value (use --value-file or stdin to avoid leaking via process listing)")
	vaultPutCmd.Flags().StringVar(&secretValueFile, "value-file", "", "Read the secret value from this file (use - for stdin)")

	vaultCmd.AddCommand(vaultPutCmd, vaultListCmd, vaultRemoveCmd)
	silenceUsageRecursive(vaultCmd)
}

var vaultCmd = &cobra.Command{
	Use:          "vault",
	Short:        "Store secrets in the confidential secrets vault (the host never sees plaintext)",
	SilenceUsage: true,
}

var vaultPutCmd = &cobra.Command{
	Use:   "put [name]",
	Short: "Seal a secret to the vault's attested key and store it under a repo",
	Long: "Store a secret in the confidential secrets vault.\n\n" +
		"The value is encrypted (EHBP) to the vault enclave's attested HPKE key, so the\n" +
		"host proxying the request only ever sees ciphertext. At boot the secret is\n" +
		"released to workloads whose sigstore provenance proves they were built from\n" +
		"--repo (any digest of it) — see design/secrets-vault-prototype.md.",
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		base, host := vaultEndpoint()
		if base == "" {
			return errNoVaultHost
		}
		if vaultOwnerRepo == "" {
			return errNoOwnerRepo
		}
		value, err := readSecretValue(cmd)
		if err != nil {
			return err
		}

		key, err := vaultKey(host)
		if err != nil {
			return err
		}
		hc, err := ehbpClientPinned(base, key)
		if err != nil {
			return err
		}
		if err := vaultPut(hc, base, vaultOwnerRepo, args[0], value); err != nil {
			return err
		}
		fmt.Printf("Stored secret %s for %s\n", args[0], vaultOwnerRepo)
		return nil
	},
}

var vaultListCmd = &cobra.Command{
	Use:     "ls",
	Aliases: []string{"list"},
	Short:   "List secret names stored under a repo",
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		base, _ := vaultEndpoint()
		if base == "" {
			return errNoVaultHost
		}
		if vaultOwnerRepo == "" {
			return errNoOwnerRepo
		}
		names, err := vaultList(base, vaultOwnerRepo)
		if err != nil {
			return err
		}
		if len(names) == 0 {
			fmt.Println("No secrets.")
			return nil
		}
		for _, n := range names {
			fmt.Println(n)
		}
		return nil
	},
}

var vaultRemoveCmd = &cobra.Command{
	Use:     "rm [name]",
	Aliases: []string{"remove", "delete"},
	Short:   "Delete a secret stored under a repo",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		base, _ := vaultEndpoint()
		if base == "" {
			return errNoVaultHost
		}
		if vaultOwnerRepo == "" {
			return errNoOwnerRepo
		}
		if err := vaultRemove(base, vaultOwnerRepo, args[0]); err != nil {
			return err
		}
		fmt.Printf("Deleted secret %s for %s\n", args[0], vaultOwnerRepo)
		return nil
	},
}

// vaultEndpoint resolves the vault from --vault or $TINFOIL_VAULT_URL into a base
// URL (for the EHBP client / HTTP calls) and a bare host (for the verifier).
// Scheme defaults to https; http is honoured for local testing.
func vaultEndpoint() (base, host string) {
	raw := strings.TrimSpace(vaultHost)
	if raw == "" {
		raw = strings.TrimSpace(os.Getenv(envVaultURL))
	}
	if raw == "" {
		return "", ""
	}
	scheme := "https"
	if strings.HasPrefix(raw, "http://") {
		scheme = "http"
	}
	raw = strings.TrimPrefix(raw, "http://")
	raw = strings.TrimPrefix(raw, "https://")
	raw = strings.TrimRight(raw, "/")
	return scheme + "://" + raw, raw
}

// vaultKey returns the HPKE key to seal secrets to: normally the vault's
// *attested* key from a fresh verification. --vault-hpke-key overrides it with a
// key supplied out-of-band — a testing affordance for a vault that can't be
// attested (e.g. a local server), never for production use.
func vaultKey(host string) (string, error) {
	if vaultHPKEKey != "" {
		return vaultHPKEKey, nil
	}
	gt, err := client.NewSecureClient(host, vaultRepo).Verify()
	if err != nil {
		return "", fmt.Errorf("verifying vault %s (%s): %w", host, vaultRepo, err)
	}
	return gt.HPKEPublicKey, nil
}

// ehbpClientPinned builds an HTTP client whose EHBP transport seals request
// bodies to the vault's HPKE key — but only after pinning the key the server
// advertises against attestedHPKE (the hex key from the attestation). Without
// the pin a tampering host could advertise a key it controls and read the
// plaintext; the pin is what makes "host sees ciphertext only" hold.
func ehbpClientPinned(base, attestedHPKE string) (*http.Client, error) {
	tr, err := ehbp.NewTransport(base)
	if err != nil {
		return nil, fmt.Errorf("fetching vault HPKE key: %w", err)
	}
	if served := tr.ServerIdentity().MarshalPublicKeyHex(); !strings.EqualFold(served, attestedHPKE) {
		return nil, fmt.Errorf("vault HPKE key mismatch: attested %s, served %s — refusing to encrypt", attestedHPKE, served)
	}
	return &http.Client{Transport: tr, Timeout: 60 * time.Second}, nil
}

type storeRequest struct {
	Repo  string `json:"repo"`
	Name  string `json:"name"`
	Value string `json:"value"`
}

func vaultPut(hc *http.Client, base, repo, name, value string) error {
	body, err := json.Marshal(storeRequest{Repo: repo, Name: name, Value: value})
	if err != nil {
		return err
	}
	resp, err := hc.Post(base+"/store", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("storing secret: %w", err)
	}
	defer resp.Body.Close()
	return vaultStatusErr(resp, "store")
}

// vaultList and vaultRemove move only secret *names*, never values, so they go
// over plain TLS to the vault rather than the EHBP-sealed channel put uses.
// (Caller authentication is the noted prototype gap — the vault does not yet
// verify who is listing or deleting.)
func vaultList(base, repo string) ([]string, error) {
	resp, err := vaultHTTP().Get(base + "/secrets?repo=" + url.QueryEscape(repo))
	if err != nil {
		return nil, fmt.Errorf("listing secrets: %w", err)
	}
	defer resp.Body.Close()
	if err := vaultStatusErr(resp, "list"); err != nil {
		return nil, err
	}
	var out struct {
		Secrets []string `json:"secrets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decoding secret list: %w", err)
	}
	return out.Secrets, nil
}

func vaultRemove(base, repo, name string) error {
	u := base + "/secrets?repo=" + url.QueryEscape(repo) + "&name=" + url.QueryEscape(name)
	req, err := http.NewRequest(http.MethodDelete, u, nil)
	if err != nil {
		return err
	}
	resp, err := vaultHTTP().Do(req)
	if err != nil {
		return fmt.Errorf("deleting secret: %w", err)
	}
	defer resp.Body.Close()
	return vaultStatusErr(resp, "delete")
}

func vaultHTTP() *http.Client { return &http.Client{Timeout: 60 * time.Second} }

func vaultStatusErr(resp *http.Response, op string) error {
	if resp.StatusCode < 400 {
		return nil
	}
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return fmt.Errorf("vault %s: %s: %s", op, resp.Status, strings.TrimSpace(string(msg)))
}
