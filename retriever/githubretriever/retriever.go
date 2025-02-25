package githubretriever

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/thomaspoignant/go-feature-flag/internal"
	"github.com/thomaspoignant/go-feature-flag/retriever/shared"

	"github.com/golang-jwt/jwt/v5"
)

// TODO popualte these from config file
const (
	ClientID       = "Iv23liDEe9v9R7OJSEV9"
	InstallID      = "61427078"
	PrivateKeyPath = "/Users/mark.mcmurray/Downloads/go-feature-flags-app.2025-02-21.private-key.pem"
	JWTExpiry      = time.Minute * 9
)

// Retriever is a configuration struct for a GitHub retriever.
type Retriever struct {
	RepositorySlug string
	Branch         string // default is main
	FilePath       string
	GithubToken    string
	Timeout        time.Duration // default is 10 seconds

	// httpClient is the http.Client if you want to override it.
	httpClient internal.HTTPClient

	// rate limit fields
	rateLimitRemaining int
	rateLimitReset     time.Time

	// Github App fields
	privateKey *rsa.PrivateKey
	// mu         sync.Mutex
	token  string
	expiry time.Time
}

func (r *Retriever) Retrieve(ctx context.Context) ([]byte, error) {
	if r.FilePath == "" || r.RepositorySlug == "" {
		return nil, fmt.Errorf("missing mandatory information filePath=%s, repositorySlug=%s", r.FilePath, r.RepositorySlug)
	}

	print("Re-running retreiver\n")
	if r.privateKey == nil {
		var err error
		r.privateKey, err = LoadPrivateKey(PrivateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load private key: %w", err)
		}
	}
	// check if token needs to be populated or refreshed
	if r.token == "" {

		now := time.Now()
		expiry := now.Add(JWTExpiry)

		claims := jwt.MapClaims{
			"iat": now.Unix(),    // Issued at
			"exp": expiry.Unix(), // Expiration
			"iss": ClientID,      // GitHub App Client ID
		}

		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		signedToken, err := token.SignedString(r.privateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to sign JWT: %w", err)
		}

		r.token = signedToken
		r.expiry = expiry

		// Refresh Auth Token - TODO break this into it's own logical block

		url := fmt.Sprintf("https://api.github.com/app/installations/%s/access_tokens", InstallID)
		req, err := http.NewRequestWithContext(ctx, "POST", url, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", r.token))
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

		client := r.httpClient
		if client == nil {
			client = http.DefaultClient
		}

		response, error := client.Do(req)
		if error != nil {
			return nil, fmt.Errorf("failed to get access token: %w", err)
		}
		defer response.Body.Close()

		if response.StatusCode != http.StatusCreated {
			return nil, fmt.Errorf("failed to get access token, status: %d", response.StatusCode)
		}

		var tokenResp struct {
			Token string `json:"token"`
		}
		if err := json.NewDecoder(response.Body).Decode(&tokenResp); err != nil {
			return nil, fmt.Errorf("failed to decode token response: %w", err)
		}

		r.GithubToken = tokenResp.Token

	}

	// default branch is main
	branch := r.Branch
	if branch == "" {
		branch = "main"
	}

	header := http.Header{}
	header.Add("Accept", "application/vnd.github.raw")
	header.Add("X-GitHub-Api-Version", "2022-11-28")
	// add header for GitHub Token if specified
	if r.GithubToken != "" {
		header.Add("Authorization", fmt.Sprintf("Bearer %s", r.GithubToken))
	}

	if r.rateLimitRemaining <= 0 && time.Now().Before(r.rateLimitReset) {
		return nil, fmt.Errorf("rate limit exceeded. Next call will be after %s", r.rateLimitReset)
	}

	URL := fmt.Sprintf(
		"https://api.github.com/repos/%s/contents/%s?ref=%s",
		r.RepositorySlug,
		r.FilePath,
		branch)

	resp, err := shared.CallHTTPAPI(ctx, URL, http.MethodGet, "", r.Timeout, header, r.httpClient)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	r.updateRateLimit(resp.Header)

	if resp.StatusCode > 399 {
		// Collect the headers to add in the error message
		ghHeaders := map[string]string{}
		for name := range resp.Header {
			if strings.HasPrefix(name, "X-") {
				ghHeaders[name] = resp.Header.Get(name)
			}
		}

		return nil, fmt.Errorf("request to %s failed with code %d."+
			" GitHub Headers: %v", URL, resp.StatusCode, ghHeaders)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}

// SetHTTPClient is here if you want to override the default http.Client we are using.
// It is also used for the tests.
func (r *Retriever) SetHTTPClient(client internal.HTTPClient) {
	r.httpClient = client
}

func (r *Retriever) updateRateLimit(headers http.Header) {
	if remaining := headers.Get("X-RateLimit-Remaining"); remaining != "" {
		if remainingInt, err := strconv.Atoi(remaining); err == nil {
			r.rateLimitRemaining = remainingInt
		}
	}

	if reset := headers.Get("X-RateLimit-Reset"); reset != "" {
		if resetInt, err := strconv.ParseInt(reset, 10, 64); err == nil {
			r.rateLimitReset = time.Unix(resetInt, 0)
		}
	}
}

// LoadPrivateKey loads a GitHub App private key from file
func LoadPrivateKey(path string) (*rsa.PrivateKey, error) {
	keyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block from private key")
	}

	parsedKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return parsedKey, nil
}
