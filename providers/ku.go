package providers

import (
	"context"
	"errors"
	"fmt"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
	"net/url"
)

type KuProvider struct {
	*ProviderData
}

var _ Provider = (*KuProvider)(nil)

const (
	kuProviderName = "Ku"
	kuDefaultScope = "*"
)

var (
	KuEmptyId = errors.New("empty id received")

	// Default Login URL for Ku.
	// Pre-parsed URL of https://ku.org/oauth/authorize.
	kuDefaultLoginURL = &url.URL{
		Scheme: "https",
		Host:   "ku.org",
		Path:   "/oauth/authorize",
	}

	// Default Redeem URL for Ku.
	// Pre-parsed URL of ttps://ku.org/oauth/token.
	kuDefaultRedeemURL = &url.URL{
		Scheme: "https",
		Host:   "ku.org",
		Path:   "/oauth/token",
	}

	// Default Validation URL for Ku.
	// Pre-parsed URL of https://ku.org/api/v3/user.
	kuDefaultValidateURL = &url.URL{
		Scheme: "https",
		Host:   "ku.org",
		Path:   "/api/v3/user",
	}
)

// NewKuProvider creates a KuProvider using the passed ProviderData
func NewKuProvider(p *ProviderData) *KuProvider {
	p.setProviderDefaults(providerDefaults{
		name:        kuProviderName,
		loginURL:    kuDefaultLoginURL,
		redeemURL:   kuDefaultRedeemURL,
		profileURL:  nil,
		validateURL: kuDefaultValidateURL,
		scope:       kuDefaultScope,
	})
	return &KuProvider{ProviderData: p}
}

// EnrichSession uses the Ku userinfo endpoint to populate the session's
// email and groups.
func (p *KuProvider) EnrichSession(ctx context.Context, s *sessions.SessionState) error {
	// Fallback to ValidateURL if ProfileURL not set for legacy compatibility
	profileURL := p.ValidateURL.String()
	if p.ProfileURL.String() != "" {
		profileURL = p.ProfileURL.String()
	}

	json, err := requests.New(profileURL).
		WithContext(ctx).
		SetHeader("Authorization", "Bearer "+s.AccessToken).
		Do().
		UnmarshalJSON()
	if err != nil {
		logger.Errorf("failed making request %v", err)
		return err
	}

	email, err := json.GetPath("data", "id").String()
	if err != nil {
		return fmt.Errorf("unable to extract id from userinfo endpoint: %w", err)
	}
	if email == "" {
		return KuEmptyId
	}
	s.Email = email

	return nil
}

func (p *KuProvider) ValidateSession(ctx context.Context, s *sessions.SessionState) bool {
	return validateToken(ctx, p, s.AccessToken, makeOIDCHeader(s.AccessToken))
}
