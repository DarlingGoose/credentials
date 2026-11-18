package oserver

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func validAuthorizationClient() *OAuthClient {
	return &OAuthClient{
		ClientID: "client-1", RedirectURIs: []string{"https://client.example/callback"},
		Scopes: []string{"openid", "profile"}, GrantTypes: []string{string(GrantTypeAuthorizationCode)},
		ResponseTypes: []string{"code"},
	}
}

func validAuthorizationRequest() AuthRequest {
	return AuthRequest{
		ResponseType: "code", ClientID: "client-1", RedirectURI: "https://client.example/callback",
		Scope: "openid profile", State: "opaque-state", CodeChallenge: GenerateCodeChallenge("verifier"),
		CodeChallengeMethod: "S256",
	}
}

func authorizationMock(client *OAuthClient) *MockOServer {
	return &MockOServer{GetClientFunc: func(context.Context, string) (*OAuthClient, error) { return client, nil }}
}

func TestValidateAuthorizationRequest(t *testing.T) {
	validClient := validAuthorizationClient()
	tests := []struct {
		name   string
		mutate func(*AuthRequest, *OAuthClient)
		want   error
	}{
		{name: "valid"},
		{name: "wrong response type", mutate: func(r *AuthRequest, _ *OAuthClient) { r.ResponseType = "token" }, want: ErrInvalidAuthorization},
		{name: "unregistered redirect", mutate: func(r *AuthRequest, _ *OAuthClient) { r.RedirectURI = "https://attacker.example/callback" }, want: ErrInvalidRedirectURI},
		{name: "redirect prefix is not exact", mutate: func(r *AuthRequest, _ *OAuthClient) { r.RedirectURI += "/extra" }, want: ErrInvalidRedirectURI},
		{name: "scope escalation", mutate: func(r *AuthRequest, _ *OAuthClient) { r.Scope += " admin" }, want: ErrInvalidAuthorization},
		{name: "missing PKCE", mutate: func(r *AuthRequest, _ *OAuthClient) { r.CodeChallenge = "" }, want: ErrInvalidAuthorization},
		{name: "plain PKCE", mutate: func(r *AuthRequest, _ *OAuthClient) { r.CodeChallengeMethod = "plain" }, want: ErrInvalidAuthorization},
		{name: "malformed S256 challenge", mutate: func(r *AuthRequest, _ *OAuthClient) { r.CodeChallenge = "not-a-sha256-challenge" }, want: ErrInvalidAuthorization},
		{name: "grant not registered", mutate: func(_ *AuthRequest, c *OAuthClient) { c.GrantTypes = []string{"client_credentials"} }, want: ErrInvalidAuthorization},
		{name: "response not registered", mutate: func(_ *AuthRequest, c *OAuthClient) { c.ResponseTypes = nil }, want: ErrInvalidAuthorization},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := validAuthorizationRequest()
			client := *validClient
			client.RedirectURIs = append([]string(nil), validClient.RedirectURIs...)
			client.Scopes = append([]string(nil), validClient.Scopes...)
			client.GrantTypes = append([]string(nil), validClient.GrantTypes...)
			client.ResponseTypes = append([]string(nil), validClient.ResponseTypes...)
			if test.mutate != nil {
				test.mutate(&req, &client)
			}
			_, err := ValidateAuthorizationRequest(context.Background(), authorizationMock(&client), req)
			if test.want == nil && err != nil {
				t.Fatalf("ValidateAuthorizationRequest() error = %v", err)
			}
			if test.want != nil && !errors.Is(err, test.want) {
				t.Fatalf("ValidateAuthorizationRequest() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestAuthorizationHandlerUsesServerPrincipalAndOpaqueState(t *testing.T) {
	var gotPrincipal AuthorizationPrincipal
	var gotState string
	server := authorizationMock(validAuthorizationClient())
	server.AuthorizeFunc = func(_ context.Context, principal AuthorizationPrincipal, req AuthRequest) (*AuthResponse, error) {
		gotPrincipal = principal
		gotState = req.State
		return &AuthResponse{Code: "code-1", State: req.State}, nil
	}
	handler := NewHandler(server, ContentTypeJSON, WithAuthorizationPrincipalResolver(
		func(*http.Request) (AuthorizationPrincipal, error) {
			return AuthorizationPrincipal{UserID: "trusted-user", AccountID: "trusted-account"}, nil
		}))
	reqData := validAuthorizationRequest()
	reqData.State = base64.StdEncoding.EncodeToString([]byte(`{"user_id":"attacker","account_id":"attacker-account"}`))
	query := url.Values{
		"response_type": {reqData.ResponseType}, "client_id": {reqData.ClientID}, "redirect_uri": {reqData.RedirectURI},
		"scope": {reqData.Scope}, "state": {reqData.State}, "code_challenge": {reqData.CodeChallenge},
		"code_challenge_method": {reqData.CodeChallengeMethod},
	}
	request := httptest.NewRequest(http.MethodGet, "/authorize?"+query.Encode(), nil)
	response := httptest.NewRecorder()
	handler.Authorize(response, request)
	if response.Code != http.StatusFound {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if gotPrincipal.UserID != "trusted-user" || gotPrincipal.AccountID != "trusted-account" {
		t.Fatalf("principal = %#v", gotPrincipal)
	}
	if gotState != reqData.State {
		t.Fatalf("state was interpreted instead of round-tripped: %q", gotState)
	}
}

func TestAuthorizationHandlerFailsClosed(t *testing.T) {
	reqData := validAuthorizationRequest()
	query := url.Values{
		"response_type": {reqData.ResponseType}, "client_id": {reqData.ClientID}, "redirect_uri": {reqData.RedirectURI},
		"scope": {reqData.Scope}, "code_challenge": {reqData.CodeChallenge}, "code_challenge_method": {reqData.CodeChallengeMethod},
	}
	request := httptest.NewRequest(http.MethodGet, "/authorize?"+query.Encode(), nil)
	response := httptest.NewRecorder()
	handler := NewHandler(authorizationMock(validAuthorizationClient()), ContentTypeJSON)
	handler.Authorize(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", response.Code)
	}

	query.Set("redirect_uri", "https://attacker.example/callback")
	request = httptest.NewRequest(http.MethodGet, "/authorize?"+query.Encode(), nil)
	response = httptest.NewRecorder()
	handler = NewHandler(authorizationMock(validAuthorizationClient()), ContentTypeJSON,
		WithAuthorizationPrincipalResolver(func(*http.Request) (AuthorizationPrincipal, error) {
			return AuthorizationPrincipal{UserID: "user-1"}, nil
		}))
	handler.Authorize(response, request)
	if response.Code != http.StatusBadRequest || response.Header().Get("Location") != "" {
		t.Fatalf("unregistered redirect status = %d, location = %q", response.Code, response.Header().Get("Location"))
	}
}

func TestValidateTokenClientRequiresRegisteredAuthenticationMethod(t *testing.T) {
	client := validAuthorizationClient()
	client.ClientSecret = "correct-secret"
	client.TokenEndpointAuth = "client_secret_basic"
	server := authorizationMock(client)

	valid := TokenRequest{ClientID: client.ClientID, ClientSecret: client.ClientSecret, ClientAuthMethod: "client_secret_basic"}
	if err := validateTokenClient(context.Background(), server, valid); err != nil {
		t.Fatalf("valid basic authentication rejected: %v", err)
	}
	wrongMethod := valid
	wrongMethod.ClientAuthMethod = "client_secret_post"
	if err := validateTokenClient(context.Background(), server, wrongMethod); err == nil {
		t.Fatal("client_secret_post accepted for client registered for client_secret_basic")
	}
	wrongSecret := valid
	wrongSecret.ClientSecret = "wrong-secret"
	if err := validateTokenClient(context.Background(), server, wrongSecret); err == nil {
		t.Fatal("wrong client secret accepted")
	}
}

func TestParseTokenRequestTracksClientAuthenticationMethod(t *testing.T) {
	handler := NewHandler(authorizationMock(nil), ContentTypeForm)

	basicRequest := httptest.NewRequest(http.MethodPost, "/token",
		strings.NewReader(url.Values{"grant_type": {string(GrantTypeAuthorizationCode)}}.Encode()))
	basicRequest.Header.Set("Content-Type", string(ContentTypeForm))
	basicRequest.SetBasicAuth("client-1", "secret-1")
	basic, err := handler.parseTokenRequest(basicRequest)
	if err != nil {
		t.Fatalf("parse basic request: %v", err)
	}
	if basic.ClientID != "client-1" || basic.ClientSecret != "secret-1" || basic.ClientAuthMethod != "client_secret_basic" {
		t.Fatalf("unexpected basic request: %#v", basic)
	}

	postRequest := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(url.Values{
		"grant_type": {string(GrantTypeAuthorizationCode)}, "client_id": {"client-2"}, "client_secret": {"secret-2"},
	}.Encode()))
	postRequest.Header.Set("Content-Type", string(ContentTypeForm))
	post, err := handler.parseTokenRequest(postRequest)
	if err != nil {
		t.Fatalf("parse post request: %v", err)
	}
	if post.ClientAuthMethod != "client_secret_post" {
		t.Fatalf("client auth method = %q", post.ClientAuthMethod)
	}

	conflict := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(url.Values{"client_id": {"client-2"}}.Encode()))
	conflict.Header.Set("Content-Type", string(ContentTypeForm))
	conflict.SetBasicAuth("client-1", "secret-1")
	if _, err := handler.parseTokenRequest(conflict); err == nil {
		t.Fatal("multiple client authentication methods were accepted")
	}
}
